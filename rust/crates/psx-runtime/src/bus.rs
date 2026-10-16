//! I/O port decoding (everything that is not main RAM or the scratchpad).
//!
//! 0x1F801000  memory control (ignored)        0x1F801040  SIO0: controllers (sio.rs)
//! 0x1F801050  SIO1 serial (absent)            0x1F801060  RAM size (ignored)
//! 0x1F801070  I_STAT / I_MASK                 0x1F801080  DMA (dma.rs)
//! 0x1F801100  root counters (timers.rs)       0x1F801800  CD-ROM (cdrom.rs)
//! 0x1F801810  GPU (gpu.rs)                    0x1F801820  MDEC (mdec.rs)
//! 0x1F801C00  SPU (spu.rs)                    0x1F802000  expansion 2 (debug, ignored)
//! 0xFFFE0130  cache control (ignored)         0x1FC00000  BIOS ROM (not present: reads 0)

use crate::{cdrom, diag, dma, gpu, machine, mdec, sio, spu, timers};
use psx_core::{Ctx, ATTENTION};
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};

pub static IO_READS: AtomicU64 = AtomicU64::new(0);
pub static IO_WRITES: AtomicU64 = AtomicU64::new(0);

pub fn io_read(_c: &mut Ctx, addr: u32, size: usize) -> u32 {
    IO_READS.fetch_add(1, Relaxed);
    let m = machine();
    let p = addr & 0x1FFF_FFFF;
    if addr == 0xFFFE_0130 {
        return 0;
    }
    let v = match p {
        0x1F80_1040..=0x1F80_104F => sio::read(m, p, size),
        0x1F80_1070..=0x1F80_1073 => {
            sio::on_istat_read(m);
            m.istat
        }
        0x1F80_1074..=0x1F80_1077 => m.imask,
        0x1F80_1080..=0x1F80_10FF => dma::read(m, p & !3),
        0x1F80_1100..=0x1F80_112F => {
            let now = m.now();
            timers::read(m, p & !3, now)
        }
        0x1F80_1800..=0x1F80_1803 => cdrom::read(m, p, size),
        0x1F80_1810 => gpu::read_data(m),
        0x1F80_1814 => {
            let now = m.now();
            m.gpu.status(now)
        }
        0x1F80_1820 => mdec::read_data(m),
        0x1F80_1824 => m.mdec.status(),
        0x1F80_1C00..=0x1F80_1FFF => spu::read(m, p, size),
        0x1F80_1000..=0x1F80_1023 | 0x1F80_1060 => 0,
        0x1F80_2000..=0x1F80_2FFF => 0,
        0x1F00_0000..=0x1F7F_FFFF => 0xFFFF_FFFF, // expansion 1: nothing connected
        0x1FC0_0000..=0x1FC7_FFFF => 0,
        _ => {
            diag::count(&format!("unmapped read {p:#010x}"));
            0
        }
    };
    // Sub-word reads of a word register return its low part (byte lanes: the offset selects).
    match size {
        1 if !(0x1F80_1800..=0x1F80_1803).contains(&p) && !(0x1F80_1040..=0x1F80_104F).contains(&p) => {
            (v >> (8 * (p & 3))) & 0xFF
        }
        2 if !(0x1F80_1C00..=0x1F80_1FFF).contains(&p) && !(0x1F80_1040..=0x1F80_104F).contains(&p) => {
            (v >> (8 * (p & 2))) & 0xFFFF
        }
        _ => v,
    }
}

pub fn io_write(_c: &mut Ctx, addr: u32, size: usize, v: u32) {
    IO_WRITES.fetch_add(1, Relaxed);
    let m = machine();
    let p = addr & 0x1FFF_FFFF;
    if addr == 0xFFFE_0130 {
        return;
    }
    match p {
        0x1F80_1040..=0x1F80_104F => sio::write(m, p, size, v),
        0x1F80_1070 => {
            // Writing 0 to a bit acknowledges it.
            let v = if size == 2 { v | 0xFFFF_0000 } else { v };
            m.istat &= v;
        }
        0x1F80_1072 => {}
        0x1F80_1074 => {
            m.imask = v & 0x7FF;
            if m.irq_pending() {
                ATTENTION.store(true, Relaxed);
            }
        }
        0x1F80_1080..=0x1F80_10FF => {
            if size >= 4 {
                dma::write(m, p, v);
            } else {
                // Byte / halfword store to a word register (libcd arms the CD-DMA interrupt with
                // `sb` to DICR+2): merge the lane into the current value. DICR's interrupt flags
                // are written as 0 outside the stored lane so nothing else is acknowledged.
                let w = p & !3;
                let shift = 8 * (p & 3);
                let mask = (if size == 1 { 0xFFu32 } else { 0xFFFF }) << shift;
                let mut cur = dma::read(m, w);
                if w == 0x1F80_10F4 {
                    cur &= 0x00FF_FFFF;
                }
                dma::write(m, w, (cur & !mask) | ((v << shift) & mask));
            }
        }
        0x1F80_1100..=0x1F80_112F => {
            let now = m.now();
            timers::write(m, p, v, now)
        }
        0x1F80_1800..=0x1F80_1803 => cdrom::write(m, p, v as u8),
        0x1F80_1810 => gpu::write_gp0(m, v),
        0x1F80_1814 => gpu::write_gp1(m, v),
        0x1F80_1820 => mdec::write_command(m, v),
        0x1F80_1824 => mdec::write_control(m, v),
        0x1F80_1C00..=0x1F80_1FFF => {
            if size == 4 {
                spu::write(m, p, v as u16);
                spu::write(m, p + 2, (v >> 16) as u16);
            } else {
                spu::write(m, p, v as u16);
            }
        }
        0x1F80_1000..=0x1F80_1023 | 0x1F80_1060 => {}
        0x1F80_2000..=0x1F80_2FFF => {
            // Expansion 2: the DTL-H2000 debug port (POST code / TTY): ignored.
        }
        _ => diag::count(&format!("unmapped write {p:#010x}")),
    }
}
