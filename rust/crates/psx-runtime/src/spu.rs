//! SPU (I/O 0x1F801C00..0x1F801FFF): 24 ADPCM voices with ADSR envelopes, pitch modulation and
//! noise, the reverb unit, CD audio input, 512 KiB sound RAM with manual/DMA transfers and the
//! sound RAM IRQ. Output is generated at 44100 Hz in step with host time ([`update`]) and handed
//! to the front end through audio.rs.

use crate::{Machine, CPU_HZ, IRQ_SPU};

const RAM: usize = 0x80000;
const POS: [i32; 5] = [0, 60, 115, 98, 122];
const NEG: [i32; 5] = [0, 0, -52, -55, -60];

#[derive(Clone, Copy, PartialEq, Default)]
enum Phase {
    #[default]
    Off,
    Attack,
    Decay,
    Sustain,
    Release,
}

#[derive(Clone, Copy, Default)]
struct Voice {
    // Registers.
    vol_l: u16,
    vol_r: u16,
    pitch: u16,
    start: u16,
    adsr_lo: u16,
    adsr_hi: u16,
    repeat: u16,
    // State.
    addr: u32,
    counter: u32,
    samples: [i16; 28],
    hist: [i32; 2],
    prev: [i32; 3], // last 3 decoded samples before the current block (interpolation)
    decoded: bool,
    flags: u8,
    phase: Phase,
    level: i32,
    env_wait: u32,
    /// The envelope already took its first step at key on (see `key_on`): skip it once.
    env_skip: bool,
    out: i32,
}

pub struct Spu {
    pub ram: Vec<u8>,
    regs: [u16; 0x200],
    v: [Voice; 24],
    endx: u32,
    cnt: u16,
    stat_irq: bool,
    xfer_addr: u32,
    irq_addr: u32,
    noise_level: i32,
    noise_count: i32,
    reverb_cur: u32,
    reverb_out: (i32, i32),
    reverb_phase: bool,
    capture_pos: u32,
    generated: u64,
    start_cycle: Option<u64>,
    pub samples_out: u64,
    /// Diagnostics: per 256-byte block of sound RAM, who wrote it last and when (milliseconds of
    /// SPU time): 1 DMA, 2 manual FIFO, 3 reverb, 4 capture buffers. Reported with each key on.
    writer: Vec<(u8, u32)>,
    /// Bytes written through the manual FIFO since the last transfer address write, and where.
    fifo_burst: (u32, u32),
}

/// Volume register value to a linear volume: fixed mode is bits 0..14 as signed 15-bit times two;
/// sweep mode (bit 15) is treated as full volume.
fn vol15(v: u16) -> i32 {
    // Fixed volume: bits 0-14 as signed 15-bit, times two. Sweep mode: treated as its level.
    if v & 0x8000 == 0 {
        ((v << 1) as i16) as i32
    } else {
        0x7FFF
    }
}

impl Spu {
    /// Diagnostics: remember that `kind` wrote the block holding `addr` now.
    #[inline]
    fn tag(&mut self, addr: usize, kind: u8) {
        let ms = (self.samples_out * 1000 / 44100) as u32;
        if let Some(w) = self.writer.get_mut((addr & (RAM - 1)) / 256) {
            *w = (kind, ms);
        }
    }

    /// Diagnostics: "who wrote the block holding `addr` last", for the event journal.
    fn writer_of(&self, addr: u32) -> String {
        let (k, ms) = self.writer[(addr as usize & (RAM - 1)) / 256];
        let who = ["nobody", "dma", "fifo", "REVERB", "CAPTURE"][k as usize];
        format!("{who} at {:.2}s", ms as f64 / 1000.0)
    }

    /// Current sound RAM transfer address (diagnostics).
    pub fn transfer_addr(&self) -> u32 {
        self.xfer_addr
    }

    /// SPU in its power-on state: 512 KiB of sound RAM, 24 silent voices, reverb off.
    pub fn new() -> Self {
        Spu {
            ram: vec![0; RAM],
            regs: [0; 0x200],
            v: [Voice::default(); 24],
            endx: 0,
            cnt: 0,
            stat_irq: false,
            xfer_addr: 0,
            irq_addr: 0,
            noise_level: 1,
            noise_count: 0,
            reverb_cur: 0,
            reverb_out: (0, 0),
            reverb_phase: false,
            capture_pos: 0,
            generated: 0,
            start_cycle: None,
            samples_out: 0,
            writer: vec![(0, 0); RAM / 256],
            fifo_burst: (0, 0),
        }
    }

    /// Raw 16-bit SPU register at byte offset `off` from 0x1F801C00.
    fn reg(&self, off: usize) -> u16 {
        self.regs[off / 2]
    }

    /// Touching sound RAM at `addr` (bytes) raises the IRQ if it is the IRQ address.
    #[inline]
    fn check_irq(&mut self, addr: u32) -> bool {
        if self.cnt & 0x40 != 0 && (addr & !7) == self.irq_addr && !self.stat_irq {
            self.stat_irq = true;
            return true;
        }
        false
    }

    /// Key on voice `n`: restart its ADPCM decoder at the start address and begin the attack phase.
    fn key_on(&mut self, n: usize) {
        let start = (self.v[n].start as u32 * 8) & (RAM as u32 - 1);
        let flags = self.ram[(start + 1) as usize];
        crate::diag::event(format!(
            "spu key on voice {n} start {start:05x} pitch {:04x} vol {:04x}/{:04x} adsr {:04x}{:04x} | data by {}{}",
            self.v[n].pitch, self.v[n].vol_l, self.v[n].vol_r, self.v[n].adsr_hi, self.v[n].adsr_lo,
            self.writer_of(start),
            if flags & 1 != 0 && flags & 2 == 0 { " | ENDS AFTER FIRST BLOCK" } else { "" }
        ));
        let v = &mut self.v[n];
        v.addr = (v.start as u32 * 8) & (RAM as u32 - 1);
        v.counter = 0;
        v.decoded = false;
        v.hist = [0; 2];
        v.prev = [0; 3];
        v.phase = Phase::Attack;
        v.level = 0;
        v.env_wait = 0;
        self.endx &= !(1 << n);
        // The SPU processes a key on at the next sample and the envelope takes its first attack
        // step right then, so ENVX is nonzero almost at once on the console. libspu's
        // SpuGetKeyStatus treats ENVX = 0 as "voice finished": without this first step a game
        // that checks soon after keying on (before the next batch of samples is mixed here) sees
        // the voice as finished and plays the next clip over it (Tekken 3's "<name> wins" lost
        // the name). The step is taken here and skipped once in `tick`.
        self.envelope(n);
        self.v[n].env_skip = true;
    }

    /// Key off voice `n`: switch its envelope to the release phase.
    fn key_off(&mut self, n: usize) {
        let v = &mut self.v[n];
        if v.phase != Phase::Off {
            v.phase = Phase::Release;
            v.env_wait = 0;
        }
    }

    /// Decode the ADPCM block at the voice's address. Returns true if the IRQ address was hit.
    fn decode_block(&mut self, n: usize) -> bool {
        let addr = self.v[n].addr as usize & (RAM - 1) & !15;
        let irq = self.check_irq(addr as u32);
        let hdr = self.ram[addr];
        let flags = self.ram[addr + 1];
        let shift = (hdr & 0xF).min(12) as i32;
        let filter = ((hdr >> 4) & 7).min(4) as usize;
        let v = &mut self.v[n];
        // Interpolation history: the last three samples of the previous block.
        if v.decoded {
            v.prev = [v.samples[25] as i32, v.samples[26] as i32, v.samples[27] as i32];
        }
        if flags & 4 != 0 {
            v.repeat = (addr / 8) as u16;
        }
        for i in 0..28 {
            let b = self.ram[addr + 2 + i / 2];
            let nib = if i & 1 == 0 { b & 0xF } else { b >> 4 };
            let raw = (((nib as i32) << 28) >> 16) >> shift;
            let s = (raw + ((v.hist[0] * POS[filter] + v.hist[1] * NEG[filter] + 32) >> 6)).clamp(-32768, 32767);
            v.hist = [s, v.hist[0]];
            v.samples[i] = s as i16;
        }
        v.flags = flags;
        v.decoded = true;
        irq
    }

    /// Decoded sample `i` of voice `n`'s current ADPCM block; negative `i` (-3..-1) reads the last
    /// samples of the previous block (the interpolator needs them across the block boundary).
    fn sample_at(&self, n: usize, i: i32) -> i32 {
        let v = &self.v[n];
        if i >= 0 {
            v.samples[i as usize] as i32
        } else {
            v.prev[(3 + i) as usize]
        }
    }

    /// Advance voice `n`'s ADSR envelope by one sample (attack, decay, sustain, release as programmed).
    fn envelope(&mut self, n: usize) {
        let v = &mut self.v[n];
        let (lo, hi) = (v.adsr_lo, v.adsr_hi);
        let (exp, dec, shift, step): (bool, bool, i32, i32) = match v.phase {
            Phase::Off => return,
            Phase::Attack => (lo & 0x8000 != 0, false, ((lo >> 10) & 0x1F) as i32, 7 - ((lo >> 8) & 3) as i32),
            Phase::Decay => (true, true, ((lo >> 4) & 0xF) as i32, -8),
            Phase::Sustain => {
                let d = hi & 0x4000 != 0;
                let st = ((hi >> 6) & 3) as i32;
                (hi & 0x8000 != 0, d, ((hi >> 8) & 0x1F) as i32, if d { -8 + st } else { 7 - st })
            }
            Phase::Release => (hi & 0x20 != 0, true, (hi & 0x1F) as i32, -8),
        };
        if v.env_wait > 0 {
            v.env_wait -= 1;
        } else {
            let mut cycles = 1u32 << (shift - 11).max(0);
            let mut s = step << (11 - shift).max(0);
            if exp && !dec && v.level > 0x6000 {
                cycles *= 4;
            }
            if exp && dec {
                s = s * v.level / 0x8000;
            }
            v.env_wait = cycles - 1;
            v.level = (v.level + s).clamp(0, 0x7FFF);
        }
        match v.phase {
            Phase::Attack if v.level >= 0x7FFF => {
                v.phase = Phase::Decay;
                v.env_wait = 0;
            }
            Phase::Decay => {
                let sustain = (((lo & 0xF) as i32) + 1) * 0x800;
                if v.level <= sustain {
                    v.phase = Phase::Sustain;
                    v.env_wait = 0;
                }
            }
            Phase::Release if v.level <= 0 => {
                v.phase = Phase::Off;
                v.level = 0;
            }
            _ => {}
        }
    }

    /// One 44.1 kHz output sample; `cd` is the CD audio input. Returns (L, R) and whether the
    /// IRQ was hit.
    fn tick(&mut self, cd: (i16, i16)) -> ((i16, i16), bool) {
        let mut irq = false;
        let (mut l, mut r) = (0i32, 0i32);
        let (mut rl, mut rr) = (0i32, 0i32);
        let kon_pmon = (self.reg(0x190) as u32) | ((self.reg(0x192) as u32) << 16);
        let non = (self.reg(0x194) as u32) | ((self.reg(0x196) as u32) << 16);
        let eon = (self.reg(0x198) as u32) | ((self.reg(0x19A) as u32) << 16);
        // Noise generator.
        let nshift = ((self.cnt >> 10) & 0xF) as i32;
        let nstep = ((self.cnt >> 8) & 3) as i32 + 4;
        self.noise_count += nstep;
        let period = 0x20000 >> nshift;
        if self.noise_count >= period {
            self.noise_count -= period;
            let l = self.noise_level;
            let bit = ((l >> 15) ^ (l >> 12) ^ (l >> 11) ^ (l >> 10) ^ 1) & 1;
            self.noise_level = ((l << 1) | bit) & 0xFFFF;
        }
        let mut prev_out = 0i32;
        for n in 0..24 {
            if self.v[n].phase == Phase::Off {
                self.v[n].out = 0;
                prev_out = 0;
                continue;
            }
            if !self.v[n].decoded {
                irq |= self.decode_block(n);
            }
            let raw = if non & (1 << n) != 0 {
                self.noise_level as i16 as i32
            } else {
                // 4-point cubic interpolation between samples i-1..i+2 (i = integer position).
                let i = (self.v[n].counter >> 12) as i32;
                let t = ((self.v[n].counter >> 4) & 0xFF) as i32;
                let p0 = self.sample_at(n, i - 3);
                let p1 = self.sample_at(n, i - 2);
                let p2 = self.sample_at(n, i - 1);
                let p3 = self.sample_at(n, i);
                let a = -p0 + 3 * p1 - 3 * p2 + p3;
                let b = 2 * p0 - 5 * p1 + 4 * p2 - p3;
                let c = -p0 + p2;
                let d = 2 * p1;
                let tt = t as i64;
                let s = ((a as i64 * tt * tt * tt / (256 * 256 * 256)) + (b as i64 * tt * tt / (256 * 256)) + (c as i64 * tt / 256) + d as i64) / 2;
                (s as i32).clamp(-32768, 32767)
            };
            if self.v[n].env_skip {
                self.v[n].env_skip = false;
            } else {
                self.envelope(n);
            }
            let v = &mut self.v[n];
            let out = (raw * v.level) >> 15;
            v.out = out;
            l += (out * vol15(v.vol_l)) >> 15;
            r += (out * vol15(v.vol_r)) >> 15;
            if eon & (1 << n) != 0 {
                rl += (out * vol15(v.vol_l)) >> 15;
                rr += (out * vol15(v.vol_r)) >> 15;
            }
            // Advance the pitch counter (with pitch modulation by the previous voice).
            let mut step = v.pitch.min(0x4000) as i32;
            if n > 0 && kon_pmon & (1 << n) != 0 {
                step = (step * (prev_out + 0x8000)) >> 15;
            }
            prev_out = out;
            v.counter += step.clamp(0, 0x3FFF) as u32;
            if v.counter >= 28 << 12 {
                v.counter -= 28 << 12;
                // Next block (loop flags of the block just finished).
                let flags = v.flags;
                if flags & 1 != 0 {
                    self.endx |= 1 << n;
                    v.addr = v.repeat as u32 * 8;
                    if flags & 2 == 0 {
                        v.phase = Phase::Release;
                        v.level = 0;
                    }
                } else {
                    v.addr = (v.addr + 16) & (RAM as u32 - 1);
                }
                irq |= self.decode_block(n);
            }
        }
        // CD audio input.
        let cd_on = self.cnt & 1 != 0;
        let (cl, cr) = if cd_on {
            let (vl, vr) = (self.reg(0x1B0) as i16 as i32, self.reg(0x1B2) as i16 as i32);
            ((cd.0 as i32 * vl) >> 15, (cd.1 as i32 * vr) >> 15)
        } else {
            (0, 0)
        };
        l += cl;
        r += cr;
        if self.cnt & 4 != 0 {
            rl += cl;
            rr += cr;
        }
        // Capture buffers: CD L/R and voices 1/3.
        let cp = self.capture_pos * 2;
        for (base, s) in [(0x000u32, cd.0 as i32), (0x400, cd.1 as i32), (0x800, self.v[1].out), (0xC00, self.v[3].out)] {
            let a = (base + cp) as usize;
            self.writer[a / 256] = (4, (self.samples_out * 1000 / 44100) as u32);
            self.ram[a..a + 2].copy_from_slice(&(s.clamp(-32768, 32767) as i16).to_le_bytes());
            irq |= self.check_irq(a as u32);
        }
        self.capture_pos = (self.capture_pos + 1) & 0x1FF;
        // Reverb (22.05 kHz).
        if self.cnt & 0x80 != 0 {
            self.reverb_phase = !self.reverb_phase;
            if self.reverb_phase {
                self.reverb_out = self.reverb(rl.clamp(-32768, 32767), rr.clamp(-32768, 32767));
            }
            let (ol, or) = self.reverb_out;
            l += (ol * self.reg(0x184) as i16 as i32) >> 15;
            r += (or * self.reg(0x186) as i16 as i32) >> 15;
        }
        let mut l = (l.clamp(-32768, 32767) * vol15(self.reg(0x180))) >> 15;
        let mut r = (r.clamp(-32768, 32767) * vol15(self.reg(0x182))) >> 15;
        if self.cnt & 0x4000 == 0 || self.cnt & 0x8000 == 0 {
            l = 0;
            r = 0;
        }
        ((l.clamp(-32768, 32767) as i16, r.clamp(-32768, 32767) as i16), irq)
    }

    /// Reverb register `i` as a signed value.
    fn rv(&self, i: usize) -> i32 {
        self.regs[(0x1C0 / 2) + i] as i16 as i32
    }
    /// Reverb address register `i` (in 8-byte units) as a sound RAM byte address.
    fn ra(&self, i: usize) -> u32 {
        self.regs[(0x1C0 / 2) + i] as u32 * 8
    }
    /// Address inside the reverb work area (wraps within mBASE..end of RAM).
    fn rbuf_addr(&self, a: u32) -> usize {
        let base = self.reg(0x1A2) as u32 * 8;
        let size = (RAM as u32).saturating_sub(base).max(2);
        let off = (self.reverb_cur + a) % size;
        ((base + off) & (RAM as u32 - 2)) as usize
    }
    /// Read a 16-bit sample from the reverb work area.
    fn rget(&self, a: u32) -> i32 {
        let i = self.rbuf_addr(a);
        i16::from_le_bytes([self.ram[i], self.ram[i + 1]]) as i32
    }
    /// Write a 16-bit sample to the reverb work area.
    fn rset(&mut self, a: u32, v: i32) {
        let i = self.rbuf_addr(a);
        self.tag(i, 3);
        self.ram[i..i + 2].copy_from_slice(&(v.clamp(-32768, 32767) as i16).to_le_bytes());
    }

    /// One stereo sample through the SPU reverb unit (same-side / different-side reflections, comb
    /// and all-pass filters); returns the wet output.
    fn reverb(&mut self, lin: i32, rin: i32) -> (i32, i32) {
        let m = |a: i32, b: i32| (a * b) >> 15;
        let (d_apf1, d_apf2) = (self.ra(0), self.ra(1));
        let (v_iir, v_comb1, v_comb2, v_comb3, v_comb4, v_wall, v_apf1, v_apf2) =
            (self.rv(2), self.rv(3), self.rv(4), self.rv(5), self.rv(6), self.rv(7), self.rv(8), self.rv(9));
        let (m_lsame, m_rsame, m_lcomb1, m_rcomb1, m_lcomb2, m_rcomb2) =
            (self.ra(10), self.ra(11), self.ra(12), self.ra(13), self.ra(14), self.ra(15));
        let (d_lsame, d_rsame, m_ldiff, m_rdiff, m_lcomb3, m_rcomb3, m_lcomb4, m_rcomb4) =
            (self.ra(16), self.ra(17), self.ra(18), self.ra(19), self.ra(20), self.ra(21), self.ra(22), self.ra(23));
        let (d_ldiff, d_rdiff, m_lapf1, m_rapf1, m_lapf2, m_rapf2) =
            (self.ra(24), self.ra(25), self.ra(26), self.ra(27), self.ra(28), self.ra(29));
        let (v_lin, v_rin) = (self.rv(30), self.rv(31));
        let lin = m(v_lin, lin);
        let rin = m(v_rin, rin);
        let back = |a: u32| a.wrapping_sub(2);
        let ls = m(lin + m(self.rget(d_lsame), v_wall) - self.rget(back(m_lsame)), v_iir) + self.rget(back(m_lsame));
        let rs = m(rin + m(self.rget(d_rsame), v_wall) - self.rget(back(m_rsame)), v_iir) + self.rget(back(m_rsame));
        let ld = m(lin + m(self.rget(d_rdiff), v_wall) - self.rget(back(m_ldiff)), v_iir) + self.rget(back(m_ldiff));
        let rd = m(rin + m(self.rget(d_ldiff), v_wall) - self.rget(back(m_rdiff)), v_iir) + self.rget(back(m_rdiff));
        self.rset(m_lsame, ls);
        self.rset(m_rsame, rs);
        self.rset(m_ldiff, ld);
        self.rset(m_rdiff, rd);
        let mut lo = m(v_comb1, self.rget(m_lcomb1)) + m(v_comb2, self.rget(m_lcomb2)) + m(v_comb3, self.rget(m_lcomb3)) + m(v_comb4, self.rget(m_lcomb4));
        let mut ro = m(v_comb1, self.rget(m_rcomb1)) + m(v_comb2, self.rget(m_rcomb2)) + m(v_comb3, self.rget(m_rcomb3)) + m(v_comb4, self.rget(m_rcomb4));
        lo = lo.clamp(-32768, 32767);
        ro = ro.clamp(-32768, 32767);
        let a1l = self.rget(m_lapf1.wrapping_sub(d_apf1));
        let a1r = self.rget(m_rapf1.wrapping_sub(d_apf1));
        lo -= m(v_apf1, a1l);
        ro -= m(v_apf1, a1r);
        self.rset(m_lapf1, lo);
        self.rset(m_rapf1, ro);
        lo = m(lo, v_apf1) + a1l;
        ro = m(ro, v_apf1) + a1r;
        let a2l = self.rget(m_lapf2.wrapping_sub(d_apf2));
        let a2r = self.rget(m_rapf2.wrapping_sub(d_apf2));
        lo -= m(v_apf2, a2l);
        ro -= m(v_apf2, a2r);
        self.rset(m_lapf2, lo);
        self.rset(m_rapf2, ro);
        lo = m(lo, v_apf2) + a2l;
        ro = m(ro, v_apf2) + a2r;
        let base = self.reg(0x1A2) as u32 * 8;
        let size = (RAM as u32).saturating_sub(base).max(2);
        self.reverb_cur = (self.reverb_cur + 2) % size;
        (lo.clamp(-32768, 32767), ro.clamp(-32768, 32767))
    }

    /// SPU register read as the CPU sees it (status, current envelope volumes, transfer address ...).
    fn read_reg(&self, off: usize) -> u16 {
        if off < 0x180 {
            let n = off / 0x10;
            return match off & 0xF {
                0xC => self.v[n].level as u16,
                0xE => self.v[n].repeat,
                _ => self.regs[off / 2],
            };
        }
        match off {
            0x19C => self.endx as u16,
            0x19E => (self.endx >> 16) as u16,
            0x1A6 => (self.xfer_addr / 8) as u16,
            0x1AA => self.cnt,
            0x1AE => (self.cnt & 0x3F) | ((self.stat_irq as u16) << 6),
            0x200..=0x25F => {
                let n = (off - 0x200) / 4;
                let o = self.v[n].out;
                (if off & 2 == 0 { (o * vol15(self.v[n].vol_l)) >> 15 } else { (o * vol15(self.v[n].vol_r)) >> 15 }) as u16
            }
            _ => self.regs.get(off / 2).copied().unwrap_or(0),
        }
    }

    /// SPU register write; returns true if it starts a voice or changes state the mixer must see now.
    fn write_reg(&mut self, off: usize, v: u16) -> bool {
        let mut irq = false;
        if off / 2 < self.regs.len() {
            self.regs[off / 2] = v;
        }
        if off < 0x180 {
            let n = off / 0x10;
            let voice = &mut self.v[n];
            match off & 0xF {
                0x0 => voice.vol_l = v,
                0x2 => voice.vol_r = v,
                0x4 => voice.pitch = v,
                0x6 => voice.start = v,
                0x8 => voice.adsr_lo = v,
                0xA => voice.adsr_hi = v,
                0xC => voice.level = (v & 0x7FFF) as i32,
                0xE => voice.repeat = v,
                _ => {}
            }
            return false;
        }
        match off {
            0x188 | 0x18A => {
                let base = if off == 0x188 { 0 } else { 16 };
                for i in 0..16 {
                    if v & (1 << i) != 0 && base + i < 24 {
                        self.key_on(base + i);
                    }
                }
            }
            0x18C | 0x18E => {
                let base = if off == 0x18C { 0 } else { 16 };
                for i in 0..16 {
                    if v & (1 << i) != 0 && base + i < 24 {
                        self.key_off(base + i);
                    }
                }
            }
            0x19C | 0x19E => {}
            0x1A2 => {
                crate::diag::event(format!("spu reverb base (mBASE) {:05x}", v as u32 * 8));
                self.reverb_cur = 0
            }
            0x1A4 => self.irq_addr = v as u32 * 8,
            0x1A6 => {
                if self.fifo_burst.1 > 0 {
                    crate::diag::event(format!("spu fifo wrote {} bytes from {:05x}", self.fifo_burst.1, self.fifo_burst.0));
                }
                self.fifo_burst = (v as u32 * 8, 0);
                self.xfer_addr = v as u32 * 8
            }
            0x1A8 => {
                // Manual write FIFO (written through at once).
                let a = self.xfer_addr as usize & (RAM - 2);
                self.fifo_burst.1 += 2;
                self.tag(a, 2);
                self.ram[a..a + 2].copy_from_slice(&v.to_le_bytes());
                irq |= self.check_irq(a as u32);
                self.xfer_addr = (self.xfer_addr + 2) & (RAM as u32 - 1);
            }
            0x1AA => {
                if (v ^ self.cnt) & 0xB0 != 0 {
                    crate::diag::event(format!(
                        "spu control {:04x}: reverb {}, transfer mode {}",
                        v, if v & 0x80 != 0 { "on" } else { "off" }, (v >> 4) & 3
                    ));
                }
                self.cnt = v;
                if v & 0x40 == 0 {
                    self.stat_irq = false;
                }
            }
            _ => {}
        }
        irq
    }
}

impl Default for Spu {
    /// Same as `Spu::new`.
    fn default() -> Self {
        Self::new()
    }
}

/// CPU read from the SPU's I/O range (0x1F801C00..0x1F801FFF).
pub fn read(m: &mut Machine, p: u32, size: usize) -> u32 {
    let off = (p - 0x1F80_1C00) as usize;
    let lo = m.spu.read_reg(off & !1) as u32;
    if size == 4 {
        lo | (m.spu.read_reg((off & !1) + 2) as u32) << 16
    } else if size == 1 {
        (lo >> (8 * (off & 1))) & 0xFF
    } else {
        lo
    }
}

/// CPU write to the SPU's I/O range.
pub fn write(m: &mut Machine, p: u32, v: u16) {
    let off = (p - 0x1F80_1C00) as usize;
    if m.spu.write_reg(off & !1, v) {
        m.raise(IRQ_SPU);
    }
}

/// DMA4 to the SPU: one word into sound RAM at the transfer address.
pub fn dma_write(m: &mut Machine, w: u32) {
    let s = &mut m.spu;
    let mut irq = false;
    for h in [w as u16, (w >> 16) as u16] {
        let a = s.xfer_addr as usize & (RAM - 2);
        s.tag(a, 1);
        s.ram[a..a + 2].copy_from_slice(&h.to_le_bytes());
        irq |= s.check_irq(a as u32);
        s.xfer_addr = (s.xfer_addr + 2) & (RAM as u32 - 1);
    }
    if irq {
        m.raise(IRQ_SPU);
    }
}

/// DMA4 from the SPU: one word from sound RAM at the transfer address.
pub fn dma_read(m: &mut Machine) -> u32 {
    let s = &mut m.spu;
    let mut v = 0u32;
    let mut irq = false;
    for i in 0..2 {
        let a = s.xfer_addr as usize & (RAM - 2);
        v |= (u16::from_le_bytes([s.ram[a], s.ram[a + 1]]) as u32) << (16 * i);
        irq |= s.check_irq(a as u32);
        s.xfer_addr = (s.xfer_addr + 2) & (RAM as u32 - 1);
    }
    if irq {
        m.raise(IRQ_SPU);
    }
    v
}

/// Generate the output samples due by `now` (44100 Hz of host time).
pub fn update(m: &mut Machine, now: u64) {
    let start = *m.spu.start_cycle.get_or_insert(now);
    let due = ((now - start) as u128 * 44100 / CPU_HZ as u128) as u64;
    let mut n = due.saturating_sub(m.spu.generated);
    if n > 4410 {
        // Host stall: skip ahead rather than produce a burst.
        m.spu.generated = due - 4410;
        n = 4410;
    }
    if n == 0 {
        return;
    }
    let mut buf = Vec::with_capacity(n as usize);
    let mut irq = false;
    for _ in 0..n {
        let cd = m.cd.audio.pop_front().unwrap_or((0, 0));
        let (s, hit) = m.spu.tick(cd);
        irq |= hit;
        buf.push(s);
    }
    m.spu.generated += n;
    m.spu.samples_out += n;
    m.shared.audio.push(&buf);
    if irq {
        m.raise(IRQ_SPU);
    }
}
