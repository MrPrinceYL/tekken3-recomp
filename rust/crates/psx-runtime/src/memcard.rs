//! Memory cards behind the HLE BIOS: the card services (_card_info, _card_load, _card_read,
//! _card_write, _new_card) and the "bu00:" / "bu10:" file system (open, lseek, read, write,
//! close, firstfile, nextfile, delete, format, rename).
//!
//! Each slot is a standard raw 128 KiB image (the .mcd / .mcr format other emulators use):
//! block 0 holds the header frame, 15 directory frames, the broken sector list and the write test
//! frame (63); blocks 1-15 hold file data, chained through the directory. Slot 1 is
//! `T3_MEMCARD` (default `memcard/slot1.mcd`, created formatted if missing); slot 2 is
//! `T3_MEMCARD2` and is empty unless set. Results reach the game as kernel events (SwCARD
//! 0xF4000001 / HwCARD 0xF0000011) a few frames later, like the real card.

use crate::kernel::read_cstr;
use crate::{diag, machine, CYCLES_PER_FRAME};
use psx_core::{Ctx, GPR_A0, GPR_V0};
use std::path::PathBuf;

pub const SW_CARD: u32 = 0xF400_0001;
pub const HW_CARD: u32 = 0xF000_0011;
pub const IOE: u32 = 0x0004;
pub const ERROR: u32 = 0x8000;
pub const TIMEOUT: u32 = 0x0100;
pub const NEWCARD: u32 = 0x2000;

const CARD_SIZE: usize = 128 * 1024;
const BLOCK: usize = 8192;
const FRAME: usize = 128;

pub struct Card {
    pub data: Vec<u8>,
    path: PathBuf,
    /// The card was (re)inserted and not yet acknowledged by _card_load / a write.
    new_flag: bool,
}

#[derive(Clone, Copy)]
struct Fd {
    slot: usize,
    first: usize,
    pos: u32,
    size: u32,
    mode: u32,
}

pub struct Cards {
    pub slots: [Option<Card>; 2],
    fds: [Option<Fd>; 16],
    find: Option<(usize, String, usize)>,
    pub ops: u64,
}

/// XOR checksum of a 128-byte directory frame (byte 127 holds it).
fn checksum(f: &[u8]) -> u8 {
    f[..127].iter().fold(0, |a, b| a ^ b)
}

/// A freshly formatted 128 KiB card image: header frame, 15 free directory entries, broken-sector list.
fn formatted() -> Vec<u8> {
    let mut d = vec![0u8; CARD_SIZE];
    d[0] = b'M';
    d[1] = b'C';
    d[127] = checksum(&d[0..128]);
    for i in 1..16 {
        let f = &mut d[i * FRAME..(i + 1) * FRAME];
        f[0] = 0xA0;
        f[8] = 0xFF;
        f[9] = 0xFF;
        f[127] = checksum(f);
    }
    for i in 16..36 {
        let f = &mut d[i * FRAME..(i + 1) * FRAME];
        f[0..4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        f[8] = 0xFF;
        f[9] = 0xFF;
        f[127] = checksum(f);
    }
    let h: Vec<u8> = d[0..128].to_vec();
    d[63 * FRAME..64 * FRAME].copy_from_slice(&h);
    d
}

impl Card {
    /// Load a card image from `path`; with `create`, write a formatted one if it does not exist.
    fn load(path: PathBuf, create: bool) -> Option<Card> {
        let data = match std::fs::read(&path) {
            Ok(d) if d.len() == CARD_SIZE => d,
            Ok(d) => {
                diag::log(format!("memcard: {} is {} bytes, not a 128 KiB card image; ignored", path.display(), d.len()));
                return None;
            }
            Err(_) if create => {
                let d = formatted();
                if let Some(dir) = path.parent() {
                    let _ = std::fs::create_dir_all(dir);
                }
                let _ = std::fs::write(&path, &d);
                diag::log(format!("memcard: created formatted card {}", path.display()));
                d
            }
            Err(_) => return None,
        };
        Some(Card { data, path, new_flag: true })
    }

    /// Write the card image back to its file (called after every change, so saves survive crashes).
    fn save(&self) {
        if let Err(e) = std::fs::write(&self.path, &self.data) {
            diag::log(format!("memcard: cannot save {}: {e}", self.path.display()));
        }
    }

    /// Directory frame `i` (1..15) of the card.
    fn entry(&self, i: usize) -> &[u8] {
        &self.data[i * FRAME..(i + 1) * FRAME]
    }

    /// Rewrite directory entry `i` (state, file size, next block, optional file name) and its checksum.
    fn set_entry(&mut self, i: usize, state: u8, size: u32, next: u16, name: Option<&str>) {
        let f = &mut self.data[i * FRAME..(i + 1) * FRAME];
        f.fill(0);
        f[0] = state;
        f[4..8].copy_from_slice(&size.to_le_bytes());
        f[8..10].copy_from_slice(&next.to_le_bytes());
        if let Some(n) = name {
            let b = n.as_bytes();
            let l = b.len().min(20);
            f[10..10 + l].copy_from_slice(&b[..l]);
        }
        f[127] = checksum(f);
    }

    /// File name stored in directory entry `i`.
    fn name(&self, i: usize) -> String {
        let f = self.entry(i);
        let end = f[10..31].iter().position(|&b| b == 0).unwrap_or(21);
        String::from_utf8_lossy(&f[10..10 + end]).into_owned()
    }

    /// Directory index (1..15) of the first block of `name`.
    fn find(&self, name: &str) -> Option<usize> {
        (1..16).find(|&i| self.entry(i)[0] == 0x51 && self.name(i) == name)
    }

    /// Blocks of the file starting at directory index `first`, in order.
    fn chain(&self, first: usize) -> Vec<usize> {
        let mut v = vec![first];
        let mut cur = first;
        while v.len() < 15 {
            let next = u16::from_le_bytes([self.entry(cur)[8], self.entry(cur)[9]]);
            if next == 0xFFFF || next as usize >= 15 {
                break;
            }
            cur = next as usize + 1;
            v.push(cur);
        }
        v
    }

    /// Size in bytes of the file whose first block is `first`.
    fn file_size(&self, first: usize) -> u32 {
        u32::from_le_bytes(self.entry(first)[4..8].try_into().unwrap())
    }
}

impl Cards {
    /// Open slot 1 (`T3_MEMCARD`, default memcard/slot1.mcd, created if missing) and slot 2 (`T3_MEMCARD2`).
    pub fn open() -> Cards {
        let p1 = std::env::var_os("T3_MEMCARD").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("memcard/slot1.mcd"));
        let p2 = std::env::var_os("T3_MEMCARD2").map(PathBuf::from);
        let s1 = Card::load(p1, true);
        let s2 = p2.and_then(|p| Card::load(p, true));
        Cards { slots: [s1, s2], fds: [None; 16], find: None, ops: 0 }
    }
}

/// Argument register a0..a3 of a BIOS call.
fn arg(c: &Ctx, i: usize) -> u32 {
    c.gpr(GPR_A0 + i)
}
/// Return value of a BIOS call (v0).
fn ret(c: &mut Ctx, v: u32) {
    c.set_gpr(GPR_V0, v);
}
/// Card slot (0 or 1) of a BIOS channel number (0x00 = slot 1, 0x10 = slot 2).
fn slot_of_chan(chan: u32) -> usize {
    ((chan >> 4) & 1) as usize
}
/// Deliver a memory card event (SwCARD / HwCARD class, spec) after `frames` vertical blanks, as the
/// real card's completion interrupt would.
fn post(class: u32, spec: u32, frames: u64) {
    let m = machine();
    let at = m.now() + frames * CYCLES_PER_FRAME;
    m.kernel.post(class, spec, at);
}

/// "bu00:NAME" -> (slot, NAME)
fn parse_path(p: &str) -> Option<(usize, String)> {
    let (dev, name) = p.split_once(':')?;
    let dev = dev.to_ascii_lowercase();
    if !dev.starts_with("bu") || dev.len() < 4 {
        return None;
    }
    let slot = (dev.as_bytes()[2] - b'0') as usize & 1;
    Some((slot, name.to_string()))
}

/// Wildcard match of a BIOS file name pattern (`?` any character, `*` the rest).
fn matches(pat: &str, name: &str) -> bool {
    let (p, n) = (pat.as_bytes(), name.as_bytes());
    let mut i = 0;
    while i < p.len() {
        match p[i] {
            b'*' => return true,
            b'?' => {
                if i >= n.len() {
                    return false;
                }
            }
            ch => {
                if i >= n.len() || n[i] != ch {
                    return false;
                }
            }
        }
        i += 1;
    }
    i == n.len()
}

/// BIOS `_bu_init`: nothing to do, the card images are already open.
pub fn bu_init(_c: &mut Ctx) {}
/// BIOS `InitCARD`: nothing to do.
pub fn init_card(_c: &mut Ctx) {}
/// BIOS `StartCARD`: nothing to do.
pub fn start_card(_c: &mut Ctx) {}

/// A0h:ABh _card_info(chan)
pub fn card_info(c: &mut Ctx, chan: u32) {
    let k = &mut machine().kernel.card;
    k.ops += 1;
    let spec = match &k.slots[slot_of_chan(chan)] {
        Some(card) if card.new_flag => NEWCARD,
        Some(_) => IOE,
        None => TIMEOUT,
    };
    post(SW_CARD, spec, 2);
    ret(c, 1);
}

/// A0h:ACh _card_load(chan): read the directory.
pub fn card_load(c: &mut Ctx, chan: u32) {
    let k = &mut machine().kernel.card;
    k.ops += 1;
    let spec = match &mut k.slots[slot_of_chan(chan)] {
        Some(card) => {
            card.new_flag = false;
            IOE
        }
        None => TIMEOUT,
    };
    post(SW_CARD, spec, 4);
    ret(c, 1);
}

/// B0h:50h _new_card(): the next write does not fail with "new card".
pub fn new_card(_c: &mut Ctx) {}

/// B0h:4Eh _card_write(chan, sector, src)
pub fn card_write(c: &mut Ctx) {
    let (chan, sector, src) = (arg(c, 0), arg(c, 1) as usize, arg(c, 2));
    let mut frame = [0u8; FRAME];
    if src != 0 {
        for (i, b) in frame.iter_mut().enumerate() {
            *b = c.ld(src + i as u32, 1) as u8;
        }
    }
    let k = &mut machine().kernel.card;
    k.ops += 1;
    let spec = match &mut k.slots[slot_of_chan(chan)] {
        Some(card) if sector < CARD_SIZE / FRAME => {
            card.new_flag = false;
            if src != 0 {
                card.data[sector * FRAME..(sector + 1) * FRAME].copy_from_slice(&frame);
                card.save();
            }
            IOE
        }
        Some(_) => ERROR,
        None => TIMEOUT,
    };
    post(HW_CARD, spec, 1);
    ret(c, 1);
}

/// B0h:4Fh _card_read(chan, sector, dst)
pub fn card_read(c: &mut Ctx) {
    let (chan, sector, dst) = (arg(c, 0), arg(c, 1) as usize, arg(c, 2));
    let data = machine().kernel.card.slots[slot_of_chan(chan)]
        .as_ref()
        .filter(|_| sector < CARD_SIZE / FRAME)
        .map(|card| card.data[sector * FRAME..(sector + 1) * FRAME].to_vec());
    let spec = match data {
        Some(d) => {
            for (i, b) in d.iter().enumerate() {
                c.st(dst + i as u32, 1, *b as u32);
            }
            IOE
        }
        None => TIMEOUT,
    };
    post(HW_CARD, spec, 1);
    ret(c, 1);
}

/// B0h:32h..45h: the file functions on bu devices.
pub fn file_call(c: &mut Ctx, n: u32) {
    machine().kernel.card.ops += 1;
    let r = match n {
        0x32 => open(c),
        0x33 => lseek(c),
        0x34 | 0x35 => rw(c, n == 0x35),
        0x36 => {
            let fd = arg(c, 0) as usize;
            let k = &mut machine().kernel.card;
            if fd < 16 && k.fds[fd].is_some() {
                k.fds[fd] = None;
                fd as u32
            } else {
                u32::MAX
            }
        }
        0x37 => 0,
        0x41 => format(c),
        0x42 => {
            let pat = read_cstr(c, arg(c, 0));
            let dst = arg(c, 1);
            match parse_path(&pat) {
                Some((slot, p)) => {
                    machine().kernel.card.find = Some((slot, p, 1));
                    find_next(c, dst)
                }
                None => 0,
            }
        }
        0x43 => find_next(c, arg(c, 0)),
        0x44 => rename(c),
        0x45 => delete(c),
        _ => u32::MAX,
    };
    ret(c, r);
}

/// BIOS `open("bu00:NAME", mode)`: open or create a save file; returns a file descriptor or -1.
fn open(c: &mut Ctx) -> u32 {
    let path = read_cstr(c, arg(c, 0));
    let mode = arg(c, 1);
    let Some((slot, name)) = parse_path(&path) else { return u32::MAX };
    let k = &mut machine().kernel.card;
    let Some(card) = k.slots[slot].as_mut() else { return u32::MAX };
    let first = if mode & 0x200 != 0 {
        if card.find(&name).is_some() {
            return u32::MAX;
        }
        let blocks = ((mode >> 16).max(1)) as usize;
        let free: Vec<usize> = (1..16).filter(|&i| matches!(card.entry(i)[0], 0xA0 | 0xA1 | 0xA2 | 0xA3)).take(blocks).collect();
        if free.len() < blocks {
            return u32::MAX;
        }
        for (j, &i) in free.iter().enumerate() {
            let last = j + 1 == free.len();
            let state = if j == 0 { 0x51 } else if last { 0x53 } else { 0x52 };
            let next = if last { 0xFFFF } else { (free[j + 1] - 1) as u16 };
            let size = if j == 0 { (blocks * BLOCK) as u32 } else { 0 };
            card.set_entry(i, state, size, next, (j == 0).then_some(name.as_str()));
            // Fresh blocks read as zero.
            card.data[i * BLOCK..(i + 1) * BLOCK].fill(0);
        }
        card.save();
        diag::log(format!("memcard: created {path} ({blocks} blocks)"));
        free[0]
    } else {
        match card.find(&name) {
            Some(i) => i,
            None => return u32::MAX,
        }
    };
    let size = card.file_size(first);
    let Some(fd) = (2..16).find(|&i| k.fds[i].is_none()) else { return u32::MAX };
    k.fds[fd] = Some(Fd { slot, first, pos: 0, size, mode });
    fd as u32
}

/// BIOS `lseek(fd, offset, whence)` on an open card file.
fn lseek(c: &mut Ctx) -> u32 {
    let (fd, off, whence) = (arg(c, 0) as usize, arg(c, 1), arg(c, 2));
    let k = &mut machine().kernel.card;
    let Some(f) = k.fds.get_mut(fd).and_then(|f| f.as_mut()) else { return u32::MAX };
    f.pos = match whence {
        0 => off,
        1 => f.pos.wrapping_add(off),
        _ => f.size.wrapping_add(off),
    };
    f.pos
}

/// BIOS `read` / `write(fd, buf, n)` on an open card file, byte by byte across its block chain,
/// clamped to the file size; returns the byte count or -1.
fn rw(c: &mut Ctx, write: bool) -> u32 {
    let (fd, buf, len) = (arg(c, 0) as usize, arg(c, 1), arg(c, 2));
    let Some(f) = machine().kernel.card.fds.get(fd).copied().flatten() else { return u32::MAX };
    let chain = match &machine().kernel.card.slots[f.slot] {
        Some(card) => card.chain(f.first),
        None => return u32::MAX,
    };
    let len = len.min(f.size.saturating_sub(f.pos));
    for i in 0..len {
        let off = (f.pos + i) as usize;
        let Some(&blk) = chain.get(off / BLOCK) else { break };
        let at = blk * BLOCK + off % BLOCK;
        if write {
            let b = c.ld(buf + i, 1) as u8;
            if let Some(card) = machine().kernel.card.slots[f.slot].as_mut() {
                card.data[at] = b;
            }
        } else {
            let b = machine().kernel.card.slots[f.slot].as_ref().map(|card| card.data[at]).unwrap_or(0);
            c.st(buf + i, 1, b as u32);
        }
    }
    if write {
        if let Some(card) = machine().kernel.card.slots[f.slot].as_ref() {
            card.save();
        }
    }
    if let Some(Some(fm)) = machine().kernel.card.fds.get_mut(fd) {
        fm.pos += len;
    }
    if f.mode & 0x8000 != 0 {
        // Asynchronous: accepted now, completion event later (about one frame per sector).
        let frames = 2 + (len as u64 / FRAME as u64) / 4;
        post(SW_CARD, IOE, frames);
        0
    } else {
        len
    }
}

/// Shared part of `firstfile` / `nextfile`: fill the next matching directory entry into `dst`.
fn find_next(c: &mut Ctx, dst: u32) -> u32 {
    let Some((slot, pat, start)) = machine().kernel.card.find.clone() else { return 0 };
    let hit = machine().kernel.card.slots[slot].as_ref().and_then(|card| {
        (start..16).find(|&i| card.entry(i)[0] == 0x51 && matches(&pat, &card.name(i))).map(|i| (i, card.name(i), card.file_size(i)))
    });
    match hit {
        Some((i, name, size)) => {
            machine().kernel.card.find = Some((slot, pat, i + 1));
            for j in 0..40 {
                c.st(dst + j, 1, 0);
            }
            for (j, b) in name.bytes().take(19).enumerate() {
                c.st(dst + j as u32, 1, b as u32);
            }
            c.st(dst + 20, 4, 0x50);
            c.st(dst + 24, 4, size);
            c.st(dst + 32, 4, i as u32);
            dst
        }
        None => {
            machine().kernel.card.find = None;
            0
        }
    }
}

/// BIOS `delete("bu00:NAME")`.
fn delete(c: &mut Ctx) -> u32 {
    let path = read_cstr(c, arg(c, 0));
    let Some((slot, name)) = parse_path(&path) else { return 0 };
    let Some(card) = machine().kernel.card.slots[slot].as_mut() else { return 0 };
    let Some(first) = card.find(&name) else { return 0 };
    for i in card.chain(first) {
        let f = &mut card.data[i * FRAME..(i + 1) * FRAME];
        f[0] = match f[0] {
            0x51 => 0xA1,
            0x52 => 0xA2,
            0x53 => 0xA3,
            s => s,
        };
        f[127] = checksum(f);
    }
    card.save();
    diag::log(format!("memcard: deleted {path}"));
    1
}

/// BIOS `rename("bu00:OLD", "bu00:NEW")`.
fn rename(c: &mut Ctx) -> u32 {
    let (from, to) = (read_cstr(c, arg(c, 0)), read_cstr(c, arg(c, 1)));
    let (Some((slot, a)), Some((_, b))) = (parse_path(&from), parse_path(&to)) else { return 0 };
    let Some(card) = machine().kernel.card.slots[slot].as_mut() else { return 0 };
    let Some(i) = card.find(&a) else { return 0 };
    let f = &mut card.data[i * FRAME..(i + 1) * FRAME];
    f[10..31].fill(0);
    let l = b.len().min(20);
    f[10..10 + l].copy_from_slice(&b.as_bytes()[..l]);
    f[127] = checksum(f);
    card.save();
    1
}

/// BIOS `format("bu00:")`: reset the card to an empty formatted image.
fn format(c: &mut Ctx) -> u32 {
    let path = read_cstr(c, arg(c, 0));
    let Some((slot, _)) = parse_path(&path) else { return 0 };
    let Some(card) = machine().kernel.card.slots[slot].as_mut() else { return 0 };
    card.data = formatted();
    card.save();
    diag::log(format!("memcard: formatted {path}"));
    1
}
