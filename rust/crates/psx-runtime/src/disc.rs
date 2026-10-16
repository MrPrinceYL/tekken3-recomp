//! The disc image: a .cue sheet with raw 2352-byte sector .bin files (data track + CD-DA).
//!
//! Positions are absolute LBAs (MSF minus 2 seconds). Every BINARY file in the cue becomes the
//! next stretch of LBAs; a track's INDEX 01 gives its start (the pregap before it, INDEX 00, still
//! belongs to the image as on a real disc).

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

pub const SECTOR: usize = 2352;

pub struct Track {
    pub number: u32,
    pub audio: bool,
    /// LBA of INDEX 01.
    pub start: u32,
    /// LBA where this track's file begins and its length in sectors.
    pub file_lba: u32,
    pub sectors: u32,
    file: usize,
}

pub struct Disc {
    files: Vec<File>,
    pub tracks: Vec<Track>,
}

/// A cue sheet MM:SS:FF time as a frame (sector) count.
fn msf_to_frames(s: &str) -> Option<u32> {
    let p: Vec<u32> = s.split(':').filter_map(|x| x.parse().ok()).collect();
    (p.len() == 3).then(|| (p[0] * 60 + p[1]) * 75 + p[2])
}

impl Disc {
    /// Open a .cue (or a single .bin, taken as one data track).
    pub fn open(path: &str) -> std::io::Result<Disc> {
        let p = Path::new(path);
        if p.extension().is_some_and(|e| e.eq_ignore_ascii_case("bin")) {
            let f = File::open(p)?;
            let n = (f.metadata()?.len() / SECTOR as u64) as u32;
            return Ok(Disc {
                files: vec![f],
                tracks: vec![Track { number: 1, audio: false, start: 0, file_lba: 0, sectors: n, file: 0 }],
            });
        }
        let text = std::fs::read_to_string(p)?;
        let dir = p.parent().map(Path::to_path_buf).unwrap_or_else(|| PathBuf::from("."));
        let mut files = Vec::new();
        let mut tracks: Vec<Track> = Vec::new();
        let mut file_lba = 0u32;
        let mut cur_file_sectors = 0u32;
        for line in text.lines() {
            let line = line.trim();
            if let Some(rest) = line.strip_prefix("FILE ") {
                if !files.is_empty() {
                    file_lba += cur_file_sectors;
                }
                let name = match (rest.find('"'), rest.rfind('"')) {
                    (Some(a), Some(b)) if b > a => rest[a + 1..b].to_string(),
                    _ => rest.split_whitespace().next().unwrap_or("").to_string(),
                };
                let f = File::open(dir.join(&name))?;
                cur_file_sectors = (f.metadata()?.len() / SECTOR as u64) as u32;
                files.push(f);
            } else if let Some(rest) = line.strip_prefix("TRACK ") {
                let mut it = rest.split_whitespace();
                let number = it.next().and_then(|n| n.parse().ok()).unwrap_or(1);
                let audio = it.next().is_some_and(|t| t == "AUDIO");
                tracks.push(Track {
                    number,
                    audio,
                    start: file_lba,
                    file_lba,
                    sectors: cur_file_sectors,
                    file: files.len().saturating_sub(1),
                });
            } else if let Some(rest) = line.strip_prefix("INDEX ") {
                let mut it = rest.split_whitespace();
                let idx: u32 = it.next().and_then(|n| n.parse().ok()).unwrap_or(1);
                if let (Some(t), Some(fr)) = (tracks.last_mut(), it.next().and_then(msf_to_frames)) {
                    if idx == 1 {
                        t.start = file_lba + fr;
                    }
                }
            }
        }
        if files.is_empty() || tracks.is_empty() {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "empty cue sheet"));
        }
        Ok(Disc { files, tracks })
    }

    /// Sectors on the whole disc (all tracks).
    pub fn total_sectors(&self) -> u32 {
        self.tracks.iter().map(|t| t.file_lba + t.sectors).max().unwrap_or(0)
    }

    /// Track containing `lba` (by file extent).
    pub fn track_at(&self, lba: u32) -> Option<&Track> {
        self.tracks.iter().rev().find(|t| lba >= t.file_lba && lba < t.file_lba + t.sectors)
    }

    /// Read one raw 2352-byte sector. Out-of-range sectors read as zeros.
    pub fn read(&mut self, lba: u32, out: &mut [u8; SECTOR]) -> bool {
        let Some(t) = self.track_at(lba) else {
            out.fill(0);
            return false;
        };
        let (file, off) = (t.file, (lba - t.file_lba) as u64 * SECTOR as u64);
        let f = &mut self.files[file];
        if f.seek(SeekFrom::Start(off)).is_err() || f.read_exact(out).is_err() {
            out.fill(0);
            return false;
        }
        true
    }
}

/// A number 0..99 as BCD (the CD-ROM controller's format).
pub fn bcd(v: u32) -> u8 {
    (((v / 10) << 4) | (v % 10)) as u8
}

/// A BCD byte as a number.
pub fn from_bcd(v: u8) -> u32 {
    ((v >> 4) as u32) * 10 + (v & 0xF) as u32
}

/// Absolute LBA -> (minute, second, frame) (with the 2-second lead-in).
pub fn lba_to_msf(lba: u32) -> (u32, u32, u32) {
    let f = lba + 150;
    (f / 4500, (f / 75) % 60, f % 75)
}
