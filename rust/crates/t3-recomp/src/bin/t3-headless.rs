//! Run the recompiled game without a window, for diagnostics: boots it, lets it run for a number
//! of seconds and saves the displayed picture once per second (`<out>/frame_NNN.png`), then
//! prints the runtime counters and the log. No input is given unless `--press` is used.
//!
//! Usage: t3-headless [seconds] [out_dir] [--press <button>@<second>[,...]]
//!   buttons: start, select, cross, circle, square, triangle, up, down, left, right, l1, r1, l2, r2

use psx_runtime::{diag, BLOCK_MISSES, CALLS, FN_ENTRIES, LAST_FN, UNKNOWN_TARGETS};
use std::sync::atomic::Ordering::Relaxed;
use std::time::{Duration, Instant};

/// Pad button bit for a `--press` name.
fn button(name: &str) -> u16 {
    // Digital pad bit order (active high here; the runtime inverts for the game).
    match name {
        "select" => 1 << 0,
        "start" => 1 << 3,
        "up" => 1 << 4,
        "right" => 1 << 5,
        "down" => 1 << 6,
        "left" => 1 << 7,
        "l2" => 1 << 8,
        "r2" => 1 << 9,
        "l1" => 1 << 10,
        "r1" => 1 << 11,
        "triangle" => 1 << 12,
        "circle" => 1 << 13,
        "cross" => 1 << 14,
        "square" => 1 << 15,
        _ => panic!("unknown button {name}"),
    }
}

/// Parse the arguments, boot, run for the requested seconds saving a PNG per second, print counters.
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut pos = args.iter().filter(|a| !a.starts_with("--"));
    let secs: u64 = pos.next().and_then(|s| s.parse().ok()).unwrap_or(30);
    let out = std::path::PathBuf::from(pos.next().cloned().unwrap_or_else(|| "headless".into()));
    let mut presses: Vec<(f32, u16)> = Vec::new();
    if let Some(i) = args.iter().position(|a| a == "--press") {
        for p in args[i + 1].split(',') {
            let (b, t) = p.split_once('@').expect("--press button@second");
            presses.push((t.parse().unwrap(), button(b)));
        }
    }
    std::fs::create_dir_all(&out).unwrap();
    let (mut cpu, shared) = t3_recomp::boot();
    shared.pad.set(0, 0, true);
    std::thread::Builder::new()
        .name("psx-cpu".into())
        .stack_size(256 << 20)
        .spawn(move || t3_recomp::run(&mut cpu))
        .unwrap();
    let start = Instant::now();
    let mut saved = 0u64;
    let mut next = 1.0f32;
    while start.elapsed().as_secs() < secs {
        std::thread::sleep(Duration::from_millis(20));
        let t = start.elapsed().as_secs_f32();
        // Hold each pressed button for 0.15 s.
        let held = presses.iter().filter(|(at, _)| t >= *at && t < at + 0.15).fold(0, |a, (_, b)| a | b);
        shared.pad.set(0, held, true);
        if t >= next {
            next += 1.0;
            let f = shared.frames.latest();
            if f.width > 0 && shared.frames.count() != saved {
                saved = shared.frames.count();
                let p = out.join(format!("frame_{:03}.png", t as u32));
                std::fs::write(&p, png(f.width, f.height, &f.rgba)).unwrap();
            }
        }
    }
    let last = LAST_FN.load(Relaxed);
    println!(
        "{} s: frames {} flips {} vblanks {} | functions entered {} | indirect calls {} | unknown targets {} | \
         mid-block entries {} | last function {:#010x} {}",
        secs,
        shared.frames.count(),
        shared.frames.flips(),
        psx_runtime::VBLANKS.load(Relaxed),
        FN_ENTRIES.load(Relaxed),
        CALLS.load(Relaxed),
        UNKNOWN_TARGETS.load(Relaxed),
        BLOCK_MISSES.load(Relaxed),
        last,
        t3_recomp::function_name(last).unwrap_or("?"),
    );
    for l in diag::tail(60) {
        println!("> {l}");
    }
    std::process::exit(0);
}

/// Minimal PNG encoder (RGBA8, zlib stored blocks).
fn png(w: u32, h: u32, rgba: &[u8]) -> Vec<u8> {
    /// CRC-32 of a PNG chunk.
    fn crc(data: &[u8]) -> u32 {
        let mut c = 0xFFFF_FFFFu32;
        for &b in data {
            c ^= b as u32;
            for _ in 0..8 {
                c = if c & 1 != 0 { 0xEDB8_8320 ^ (c >> 1) } else { c >> 1 };
            }
        }
        !c
    }
    /// Append one PNG chunk (length, type, data, CRC).
    fn chunk(out: &mut Vec<u8>, kind: &[u8], data: &[u8]) {
        out.extend_from_slice(&(data.len() as u32).to_be_bytes());
        let mut c = kind.to_vec();
        c.extend_from_slice(data);
        out.extend_from_slice(&c);
        out.extend_from_slice(&crc(&c).to_be_bytes());
    }
    let mut raw = Vec::with_capacity((w as usize * 4 + 1) * h as usize);
    for y in 0..h as usize {
        raw.push(0);
        raw.extend_from_slice(&rgba[y * w as usize * 4..(y + 1) * w as usize * 4]);
    }
    let mut z = vec![0x78, 0x01];
    let (mut a, mut b) = (1u32, 0u32);
    for &x in &raw {
        a = (a + x as u32) % 65521;
        b = (b + a) % 65521;
    }
    let mut chunks = raw.chunks(65535).peekable();
    while let Some(c) = chunks.next() {
        z.push(if chunks.peek().is_none() { 1 } else { 0 });
        z.extend_from_slice(&(c.len() as u16).to_le_bytes());
        z.extend_from_slice(&(!(c.len() as u16)).to_le_bytes());
        z.extend_from_slice(c);
    }
    z.extend_from_slice(&((b << 16) | a).to_be_bytes());
    let mut out = b"\x89PNG\r\n\x1a\n".to_vec();
    let mut ihdr = Vec::new();
    ihdr.extend_from_slice(&w.to_be_bytes());
    ihdr.extend_from_slice(&h.to_be_bytes());
    ihdr.extend_from_slice(&[8, 6, 0, 0, 0]);
    chunk(&mut out, b"IHDR", &ihdr);
    chunk(&mut out, b"IDAT", &z);
    chunk(&mut out, b"IEND", &[]);
    out
}
