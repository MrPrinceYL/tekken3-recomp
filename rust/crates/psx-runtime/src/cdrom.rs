//! CD-ROM controller (I/O 0x1F801800..0x1F801803).
//!
//! Commands answer through the response FIFO with interrupts INT1 (data / report), INT2
//! (second response), INT3 (first response), INT4 (data end) and INT5 (error), delivered one at
//! a time: the next waits until the game has acknowledged the previous one, as on hardware.
//! Reading delivers a sector every 1/75 s (1/150 s at double speed); XA-ADPCM sectors are decoded
//! into the CD audio stream (xa.rs) instead when ADPCM playback is enabled, and Play streams the
//! audio track. The CD audio stream is mixed by the SPU.

use std::sync::atomic::{AtomicU32, Ordering::Relaxed};
use crate::disc::{self, bcd, from_bcd, Disc, SECTOR};
use crate::{diag, xa, Machine, CPU_HZ, IRQ_CDROM};
use std::collections::VecDeque;

const FIRST_RESPONSE: u64 = 25_000;

/// Fast loading option (settings menu): data reads run this many times faster than the console
/// (1 = original speed, the default; at most 8). Streams are never sped up (see `fast_factor`).
pub static FAST_LOAD: AtomicU32 = AtomicU32::new(1);
const SECOND_RESPONSE: u64 = 60_000;

const STAT_ERROR: u8 = 0x01;
const STAT_MOTOR: u8 = 0x02;
const STAT_READ: u8 = 0x20;
const STAT_SEEK: u8 = 0x40;
const STAT_PLAY: u8 = 0x80;

struct Pending {
    at: u64,
    int: u8,
    resp: Vec<u8>,
    /// Sector data that becomes readable when this INT1 is delivered.
    sector: Option<Box<[u8; SECTOR]>>,
    /// Clears BUSYSTS when delivered (first response of a command).
    first: bool,
}

#[derive(PartialEq, Clone, Copy)]
enum Activity {
    Idle,
    Seeking { then: After, done: u64 },
    Reading,
    Playing,
}

#[derive(PartialEq, Clone, Copy)]
enum After {
    Read,
    Play,
    SeekDone,
}

pub struct Cdrom {
    disc: Option<Disc>,
    index: u8,
    params: VecDeque<u8>,
    response: VecDeque<u8>,
    pub irq_flags: u8,
    pub irq_enable: u8,
    queue: VecDeque<Pending>,
    busy: bool,
    stat: u8,
    pub mode: u8,
    setloc: u32,
    setloc_pending: bool,
    pos: u32,
    activity: Activity,
    next_sector: u64,
    ready: Option<Box<[u8; SECTOR]>>,
    /// Command of the running read (0x06 ReadN / 0x1B ReadS), for the fast loading option.
    read_cmd: u8,
    /// File / channel of the last XA audio sector played (event journal: clip changes).
    last_xa: u16,
    /// The drive's current sector buffer: the last sector loaded into the data FIFO. Resetting
    /// the FIFO (request BFRD=0) keeps it, and BFRD=1 with no newer sector loads it again.
    current: Option<Box<[u8; SECTOR]>>,
    /// When `ready` was delivered (its INT1).
    ready_at: u64,
    data: Vec<u8>,
    data_pos: usize,
    request: u8,
    filter_file: u8,
    filter_chan: u8,
    muted: bool,
    adpcm_muted: bool,
    vol: [u8; 4],
    vol_next: [u8; 4],
    last_header: [u8; 8],
    play_track_end: u32,
    pub xa: xa::XaDecoder,
    /// CD audio (XA or CD-DA) at 44100 Hz, consumed by the SPU mixer.
    pub audio: VecDeque<(i16, i16)>,
    pub sectors_read: u64,
}

impl Cdrom {
    /// CD-ROM controller with `disc` inserted (or an empty drive for None).
    pub fn new(disc: Option<Disc>) -> Self {
        Cdrom {
            disc,
            index: 0,
            params: VecDeque::new(),
            response: VecDeque::new(),
            irq_flags: 0,
            irq_enable: 0x1F, // as the BIOS leaves it after its own CD init
            queue: VecDeque::new(),
            busy: false,
            stat: STAT_MOTOR,
            mode: 0,
            setloc: 0,
            setloc_pending: false,
            pos: 0,
            activity: Activity::Idle,
            next_sector: 0,
            ready: None,
            read_cmd: 0,
            last_xa: 0xFFFF,
            current: None,
            ready_at: 0,
            data: Vec::new(),
            data_pos: 0,
            request: 0,
            filter_file: 0,
            filter_chan: 0,
            muted: false,
            adpcm_muted: false,
            vol: [0x80, 0, 0x80, 0],
            vol_next: [0x80, 0, 0x80, 0],
            last_header: [0; 8],
            play_track_end: 0,
            xa: xa::XaDecoder::default(),
            audio: VecDeque::new(),
            sectors_read: 0,
        }
    }

    /// CPU cycles per sector at the current speed (75 or 150 sectors per second).
    fn sector_cycles(&self) -> u64 {
        let base = if self.mode & 0x80 != 0 { CPU_HZ / 150 } else { CPU_HZ / 75 };
        base / self.fast_factor()
    }

    /// Speed-up for the running read (1 = the console's speed). Only plain data reads (ReadN with
    /// XA-ADPCM off) are sped up; streams (ReadS: XA music, movies) keep the console's rate,
    /// since they are played back as they arrive.
    fn fast_factor(&self) -> u64 {
        if self.read_cmd == 0x06 && self.mode & 0x40 == 0 && self.activity != Activity::Playing {
            FAST_LOAD.load(Relaxed).clamp(1, 8) as u64
        } else {
            1
        }
    }

    /// Queue an interrupt (INT1..INT5 with its response bytes) for time `at`.
    fn push(&mut self, at: u64, int: u8, resp: Vec<u8>, first: bool) {
        self.queue.push_back(Pending { at, int, resp, sector: None, first });
    }

    /// Status register (0x1F801800): index, parameter FIFO, response FIFO, data FIFO and busy bits.
    fn status_reg(&self) -> u8 {
        let mut s = self.index & 3;
        s |= (self.params.is_empty() as u8) << 3;
        s |= ((self.params.len() < 16) as u8) << 4;
        s |= (!self.response.is_empty() as u8) << 5;
        s |= ((self.data_pos < self.data.len()) as u8) << 6;
        s |= (self.busy as u8) << 7;
        s
    }

    /// The drive's stat byte (motor, reading / seeking / playing, error, shell open).
    fn stat_byte(&self) -> u8 {
        let mut s = self.stat & (STAT_MOTOR | STAT_ERROR);
        match self.activity {
            Activity::Reading => s |= STAT_READ,
            Activity::Playing => s |= STAT_PLAY,
            Activity::Seeking { .. } => s |= STAT_SEEK,
            Activity::Idle => {}
        }
        s
    }

    /// CPU cycles a seek from the current position to `target` takes.
    fn seek_cycles(&self, target: u32) -> u64 {
        let d = (target as i64 - self.pos as i64).unsigned_abs();
        50_000 + d.min(200_000) * 30
    }

    /// Execute a controller command (Getstat, Setloc, ReadN/ReadS, Play, Pause, Init, Setmode,
    /// Setfilter, GetlocL/P, GetTN/TD, SeekL/P, Test, GetID, ReadTOC ...) with its parameters.
    fn command(&mut self, cmd: u8, now: u64) {
        let p: Vec<u8> = self.params.drain(..).collect();
        crate::diag::event(format!("cd cmd {cmd:02x} {p:02x?} (at sector {}, mode {:02x})", self.pos, self.mode));
        let t1 = now + FIRST_RESPONSE;
        self.busy = true;
        diag::count(&format!("cd cmd {cmd:02x}"));
        match cmd {
            0x01 => self.push(t1, 3, vec![self.stat_byte()], true),
            0x02 => {
                if p.len() >= 3 {
                    let (mm, ss, ff) = (from_bcd(p[0]), from_bcd(p[1]), from_bcd(p[2]));
                    self.setloc = ((mm * 60 + ss) * 75 + ff).saturating_sub(150);
                    self.setloc_pending = true;
                }
                self.push(t1, 3, vec![self.stat_byte()], true);
            }
            0x03 => {
                // Play [track]
                let track = p.first().map(|&t| from_bcd(t)).unwrap_or(0);
                let mut target = if self.setloc_pending { self.setloc } else { self.pos };
                if track > 0 {
                    if let Some(t) = self.disc.as_ref().and_then(|d| d.tracks.iter().find(|t| t.number == track)) {
                        target = t.start;
                    }
                }
                self.setloc_pending = false;
                self.play_track_end = self
                    .disc
                    .as_ref()
                    .and_then(|d| d.track_at(target).map(|t| t.file_lba + t.sectors))
                    .unwrap_or(u32::MAX);
                self.stat |= STAT_MOTOR;
                self.push(t1, 3, vec![self.stat_byte() | STAT_PLAY], true);
                let done = now + self.seek_cycles(target);
                self.pos = target;
                self.activity = Activity::Seeking { then: After::Play, done };
            }
            0x04 | 0x05 => self.push(t1, 3, vec![self.stat_byte()], true), // Forward / Backward
            0x06 | 0x1B => {
                // ReadN / ReadS
                self.read_cmd = cmd;
                self.stat |= STAT_MOTOR;
                self.push(t1, 3, vec![self.stat_byte()], true);
                let target = if self.setloc_pending { self.setloc } else { self.pos };
                self.setloc_pending = false;
                let seek = if target == self.pos && self.activity == Activity::Reading { 0 } else { self.seek_cycles(target) };
                let seek = seek / self.fast_factor();
                self.pos = target;
                self.activity = Activity::Seeking { then: After::Read, done: now + seek };
                // Drop audio of a previous stream.
                self.xa.reset();
            }
            0x07 => {
                self.stat |= STAT_MOTOR;
                self.push(t1, 3, vec![self.stat_byte()], true);
                self.push(t1 + SECOND_RESPONSE, 2, vec![self.stat_byte()], false);
            }
            0x08 => {
                // Stop
                let s = self.stat_byte();
                self.activity = Activity::Idle;
                self.push(t1, 3, vec![s], true);
                self.stat &= !STAT_MOTOR;
                self.push(t1 + SECOND_RESPONSE * 4, 2, vec![self.stat_byte()], false);
            }
            0x09 => {
                // Pause
                let s = self.stat_byte();
                self.push(t1, 3, vec![s], true);
                let delay = if self.activity == Activity::Idle { 7000 } else { self.sector_cycles() };
                self.activity = Activity::Idle;
                self.drop_sector_irqs();
                self.push(t1 + delay, 2, vec![self.stat_byte()], false);
            }
            0x0A => {
                // Init
                self.mode = 0x20;
                self.activity = Activity::Idle;
                self.stat = STAT_MOTOR;
                self.drop_sector_irqs();
                self.push(t1, 3, vec![self.stat_byte()], true);
                self.push(t1 + SECOND_RESPONSE, 2, vec![self.stat_byte()], false);
            }
            0x0B => {
                self.muted = true;
                self.push(t1, 3, vec![self.stat_byte()], true);
            }
            0x0C => {
                self.muted = false;
                self.push(t1, 3, vec![self.stat_byte()], true);
            }
            0x0D => {
                self.filter_file = p.first().copied().unwrap_or(0);
                self.filter_chan = p.get(1).copied().unwrap_or(0);
                self.push(t1, 3, vec![self.stat_byte()], true);
            }
            0x0E => {
                self.mode = p.first().copied().unwrap_or(0);
                self.push(t1, 3, vec![self.stat_byte()], true);
            }
            0x0F => {
                let r = vec![self.stat_byte(), self.mode, 0, self.filter_file, self.filter_chan];
                self.push(t1, 3, r, true);
            }
            0x10 => self.push(t1, 3, self.last_header.to_vec(), true),
            0x11 => {
                let r = self.position_report(false);
                self.push(t1, 3, r, true);
            }
            0x12 => {
                self.push(t1, 3, vec![self.stat_byte()], true);
                self.push(t1 + SECOND_RESPONSE, 2, vec![self.stat_byte()], false);
            }
            0x13 => {
                let last = self.disc.as_ref().map(|d| d.tracks.len() as u32).unwrap_or(1);
                self.push(t1, 3, vec![self.stat_byte(), 1, bcd(last)], true);
            }
            0x14 => {
                let t = p.first().map(|&t| from_bcd(t)).unwrap_or(0);
                let lba = match &self.disc {
                    Some(d) if t == 0 => d.total_sectors(),
                    Some(d) => d.tracks.iter().find(|x| x.number == t).map(|x| x.start).unwrap_or(0),
                    None => 0,
                };
                let (mm, ss, _) = disc::lba_to_msf(lba);
                self.push(t1, 3, vec![self.stat_byte(), bcd(mm), bcd(ss)], true);
            }
            0x15 | 0x16 => {
                // SeekL / SeekP
                self.push(t1, 3, vec![self.stat_byte()], true);
                let target = self.setloc;
                self.setloc_pending = false;
                let done = now + self.seek_cycles(target);
                self.pos = target;
                self.activity = Activity::Seeking { then: After::SeekDone, done };
            }
            0x19 => {
                let sub = p.first().copied().unwrap_or(0);
                let r = match sub {
                    0x20 => vec![0x94, 0x09, 0x19, 0xC0],
                    0x04 | 0x05 => vec![self.stat_byte()],
                    _ => vec![self.stat_byte()],
                };
                self.push(t1, 3, r, true);
            }
            0x1A => {
                self.push(t1, 3, vec![self.stat_byte()], true);
                if self.disc.is_some() {
                    self.push(t1 + SECOND_RESPONSE, 2, vec![0x02, 0x00, 0x20, 0x00, b'S', b'C', b'E', b'A'], false);
                } else {
                    self.push(t1 + SECOND_RESPONSE, 5, vec![0x08, 0x40, 0, 0, 0, 0, 0, 0], false);
                }
            }
            0x1C => {
                self.mode = 0;
                self.activity = Activity::Idle;
                self.stat = STAT_MOTOR;
                self.queue.clear();
                self.push(t1, 3, vec![self.stat_byte()], true);
            }
            0x1E => {
                self.push(t1, 3, vec![self.stat_byte()], true);
                self.push(t1 + SECOND_RESPONSE * 4, 2, vec![self.stat_byte()], false);
            }
            _ => {
                diag::log(format!("cdrom: unknown command {cmd:#04x} {p:02x?}"));
                self.push(t1, 5, vec![self.stat_byte() | STAT_ERROR, 0x40], true);
            }
        }
    }

    /// Drop queued sector interrupts (a new read or a pause cancels sectors not yet delivered).
    fn drop_sector_irqs(&mut self) {
        self.queue.retain(|p| p.int != 1);
    }

    /// Response of GetlocP: track, index and relative / absolute time of the current position.
    fn position_report(&self, _alternate: bool) -> Vec<u8> {
        let lba = self.pos;
        let (track, start) = self
            .disc
            .as_ref()
            .and_then(|d| d.tracks.iter().rev().find(|t| lba >= t.file_lba && lba < t.file_lba + t.sectors).map(|t| (t.number, t.start)))
            .unwrap_or((1, 0));
        let index = if lba >= start { 1 } else { 0 };
        let rel = lba.abs_diff(start);
        let (am, asx, af) = disc::lba_to_msf(lba);
        let (rm, rs, rf) = (rel / 4500, (rel / 75) % 60, rel % 75);
        vec![bcd(track), bcd(index), bcd(rm), bcd(rs), bcd(rf), bcd(am), bcd(asx), bcd(af)]
    }

    /// One sector time elapsed while reading or playing.
    fn sector_tick(&mut self, at: u64) {
        let Some(d) = self.disc.as_mut() else { return };
        let mut buf = Box::new([0u8; SECTOR]);
        d.read(self.pos, &mut buf);
        let lba = self.pos;
        self.pos += 1;
        self.sectors_read += 1;
        match self.activity {
            Activity::Reading => {
                self.last_header.copy_from_slice(&buf[12..20]);
                let mode2 = buf[15] == 2;
                let sub = buf[18];
                let audio = mode2 && sub & 0x04 != 0 && sub & 0x20 != 0;
                if self.mode & 0x08 != 0 && audio {
                    // XA filter: only the selected file / channel's ADPCM sectors.
                    if buf[16] != self.filter_file || buf[17] != self.filter_chan {
                        return;
                    }
                }
                if audio && self.mode & 0x40 != 0 {
                    let clip = (buf[16] as u16) << 8 | buf[17] as u16;
                    if clip != self.last_xa {
                        self.last_xa = clip;
                        crate::diag::event(format!(
                            "xa audio file {} channel {} starts at sector {lba} (muted {}, adpcm muted {})",
                            buf[16], buf[17], self.muted, self.adpcm_muted
                        ));
                    }
                    if !self.muted && !self.adpcm_muted {
                        let vol = self.vol;
                        self.xa.decode_sector(&buf[..], &mut self.audio, vol);
                    }
                    return;
                }
                // Data: INT1 with the sector.
                let pending_int1 = self.queue.iter().filter(|p| p.int == 1).count();
                if pending_int1 >= 2 {
                    // The game did not take the previous sectors in time: overrun, keep the newest.
                    if let Some(i) = self.queue.iter().position(|p| p.int == 1) {
                        self.queue.remove(i);
                    }
                }
                let stat = self.stat_byte();
                self.queue.push_back(Pending { at, int: 1, resp: vec![stat], sector: Some(buf), first: false });
            }
            Activity::Playing => {
                if lba >= self.play_track_end {
                    self.activity = Activity::Idle;
                    if self.mode & 0x02 != 0 {
                        let s = self.stat_byte();
                        self.push(at, 4, vec![s], false);
                    }
                    self.pos -= 1;
                    return;
                }
                if !self.muted {
                    // CD-DA: 588 stereo 16-bit samples, through the CD volume matrix.
                    for f in buf.chunks_exact(4) {
                        let l = i16::from_le_bytes([f[0], f[1]]) as i32;
                        let r = i16::from_le_bytes([f[2], f[3]]) as i32;
                        self.audio.push_back(xa::apply_volume(l, r, self.vol));
                    }
                    while self.audio.len() > 44100 {
                        self.audio.pop_front();
                    }
                }
                if self.mode & 0x04 != 0 {
                    // Report: at absolute frames 00/20/40 (absolute time) and 10/30/50 (relative
                    // time, seconds with bit 7 set).
                    let f = (lba + 150) % 75;
                    if f % 10 == 0 && f <= 50 && self.queue.iter().all(|p| p.int != 1) {
                        let (track, start) = self
                            .disc
                            .as_ref()
                            .and_then(|d| d.track_at(lba).map(|t| (t.number, t.start)))
                            .unwrap_or((1, 0));
                        let index = if lba >= start { 1 } else { 0 };
                        let r = if (f / 10) % 2 == 0 {
                            let (am, asx, af) = disc::lba_to_msf(lba);
                            vec![self.stat_byte(), bcd(track), bcd(index), bcd(am), bcd(asx), bcd(af), 0, 0]
                        } else {
                            let rel = lba.abs_diff(start);
                            vec![self.stat_byte(), bcd(track), bcd(index), bcd(rel / 4500), bcd((rel / 75) % 60) | 0x80, bcd(rel % 75), 0, 0]
                        };
                        self.push(at, 1, r, false);
                    }
                }
            }
            _ => {}
        }
    }
}

/// CPU read from the CD-ROM registers (0x1F801800..0x1F801803, banked by the index register).
pub fn read(m: &mut Machine, p: u32, size: usize) -> u32 {
    let cd = &mut m.cd;
    match p & 3 {
        0 => cd.status_reg() as u32,
        1 => cd.response.pop_front().unwrap_or(0) as u32,
        2 => {
            let mut v = 0u32;
            for i in 0..size.min(4) {
                v |= (data_byte(cd) as u32) << (8 * i);
            }
            v
        }
        _ => {
            if cd.index & 1 == 0 {
                (cd.irq_enable | 0xE0) as u32
            } else {
                (cd.irq_flags | 0xE0) as u32
            }
        }
    }
}

/// Next byte of the data FIFO (the loaded sector).
fn data_byte(cd: &mut Cdrom) -> u8 {
    if cd.data_pos < cd.data.len() {
        cd.data_pos += 1;
        cd.data[cd.data_pos - 1]
    } else {
        // Reading past the end repeats the last byte pair on hardware; zeros are close enough.
        0
    }
}

/// DMA3 from the CD-ROM: one word of the data FIFO.
pub fn dma_read(m: &mut Machine) -> u32 {
    let cd = &mut m.cd;
    let mut v = 0u32;
    for i in 0..4 {
        v |= (data_byte(cd) as u32) << (8 * i);
    }
    v
}

/// CPU write to the CD-ROM registers: index, command, parameters, interrupt enable / acknowledge,
/// request (BFRD loads a sector into the data FIFO) and the CD audio volume matrix.
pub fn write(m: &mut Machine, p: u32, v: u8) {
    let now = m.now();
    let cd = &mut m.cd;
    match (p & 3, cd.index & 3) {
        (0, _) => cd.index = v & 3,
        (1, 0) => cd.command(v, now),
        (1, 3) => cd.vol_next[2] = v, // right -> right
        (1, _) => {}
        (2, 0) => {
            if cd.params.len() < 16 {
                cd.params.push_back(v);
            }
        }
        (2, 1) => {
            cd.irq_enable = v & 0x1F;
            check_irq(m);
        }
        (2, 2) => cd.vol_next[0] = v, // left -> left
        (2, 3) => cd.vol_next[3] = v, // right -> left
        (3, 0) => {
            cd.request = v;
            if v & 0x80 != 0 {
                // Load the newest delivered sector into the data FIFO. A sector that was only
                // partly read (libcd's streamer reads just the header of sectors it skips) is
                // replaced; requesting again with no new sector continues the current one, or
                // after a FIFO reset (BFRD=0) loads it again from its start: libcd checks the
                // header, resets the FIFO and then requests the sector again for its DMA.
                let (off, len) = match cd.mode & 0x30 {
                    0x20 | 0x30 => (12, 0x924),
                    0x10 => (12, 0x918),
                    _ => (24, 0x800),
                };
                if let Some(s) = cd.ready.take() {
                    cd.data.clear();
                    cd.data.extend_from_slice(&s[off..off + len]);
                    cd.data_pos = 0;
                    cd.current = Some(s);
                } else if cd.data.is_empty() {
                    if let Some(s) = cd.current.as_ref() {
                        cd.data.extend_from_slice(&s[off..off + len]);
                        cd.data_pos = 0;
                    }
                }
            } else {
                cd.data.clear();
                cd.data_pos = 0;
            }
        }
        (3, 1) => {
            cd.irq_flags &= !(v & 0x1F);
            if v & 0x40 != 0 {
                cd.params.clear();
            }
            if cd.irq_flags == 0 {
                cd.response.clear();
                deliver(m, now);
            }
        }
        (3, 2) => cd.vol_next[1] = v, // left -> right
        (3, 3) => {
            cd.adpcm_muted = v & 1 != 0;
            if v & 0x20 != 0 {
                cd.vol = cd.vol_next;
            }
        }
        _ => {}
    }
}

/// Raise IRQ2 if an enabled CD interrupt is pending.
fn check_irq(m: &mut Machine) {
    if m.cd.irq_flags & m.cd.irq_enable & 0x1F != 0 {
        m.raise(IRQ_CDROM);
    }
}

/// Deliver the next queued interrupt if the previous one was acknowledged and it is due.
fn deliver(m: &mut Machine, now: u64) {
    let cd = &mut m.cd;
    if cd.irq_flags != 0 {
        return;
    }
    let Some(front) = cd.queue.front() else { return };
    if front.at > now {
        return;
    }
    // The drive hands the CPU one sector per sector period. A data INT1 that was already due when
    // the previous one was acknowledged (the game ran late) waits until that sector has been
    // loaded into the data FIFO (or half a period passed), so acknowledging it doesn't swap the
    // sector the game is about to read (CdRead reads the header after the acknowledge; the swap
    // made it see the next sector: "CdRead: sector error").
    if front.int == 1 && front.sector.is_some() && cd.ready.is_some() && now < cd.ready_at + cd.sector_cycles() / 2 {
        return;
    }
    let p = cd.queue.pop_front().unwrap();
    cd.irq_flags = p.int;
    cd.response.clear();
    cd.response.extend(p.resp);
    if p.first {
        cd.busy = false;
    }
    if let Some(s) = p.sector {
        cd.ready = Some(s);
        cd.ready_at = now;
    }
    check_irq(m);
}

/// Advance seeking / reading / playing to `now` and deliver due interrupts.
pub fn update(m: &mut Machine, now: u64) {
    let cd = &mut m.cd;
    if let Activity::Seeking { then, done } = cd.activity {
        if now >= done {
            match then {
                After::Read => {
                    cd.activity = Activity::Reading;
                    cd.next_sector = done + cd.sector_cycles();
                }
                After::Play => {
                    cd.activity = Activity::Playing;
                    cd.next_sector = done + CPU_HZ / 75;
                }
                After::SeekDone => {
                    cd.activity = Activity::Idle;
                    let s = cd.stat_byte();
                    cd.push(done, 2, vec![s], false);
                }
            }
        }
    }
    let mut guard = 0;
    while matches!(cd.activity, Activity::Reading | Activity::Playing) && now >= cd.next_sector && guard < 8 {
        if cd.fast_factor() > 1 && (cd.irq_flags == 1 || cd.queue.iter().any(|p| p.int == 1)) {
            // Fast loading: the drive waits until the game took the previous sector (the device
            // clock runs in ~1 ms steps, so faster sectors would otherwise overrun and be lost).
            cd.next_sector = now + cd.sector_cycles();
            break;
        }
        let at = cd.next_sector;
        let period = if cd.activity == Activity::Playing && cd.mode & 0x80 == 0 { CPU_HZ / 75 } else { cd.sector_cycles() };
        cd.next_sector += period;
        cd.sector_tick(at);
        guard += 1;
    }
    if guard == 8 && now > cd.next_sector {
        cd.next_sector = now; // far behind (host stall): resynchronise
    }
    deliver(m, now);
}
