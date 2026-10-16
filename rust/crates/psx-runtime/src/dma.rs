//! DMA controller (I/O 0x1F801080..0x1F8010FF): seven channels, DPCR and DICR.
//!
//! Transfers run to completion as soon as a channel is started (the CPU is stalled during DMA on
//! hardware too); the completion interrupt is raised through DICR like the real controller.
//! Channels: 0 MDEC in, 1 MDEC out, 2 GPU, 3 CD-ROM, 4 SPU, 5 PIO (unused), 6 OT clear.

use crate::{cdrom, diag, gpu, mdec, spu, Machine, IRQ_DMA};

#[derive(Default, Clone, Copy)]
pub struct Channel {
    pub madr: u32,
    pub bcr: u32,
    pub chcr: u32,
}

#[derive(Default)]
pub struct Dma {
    pub ch: [Channel; 7],
    pub dpcr: u32,
    pub dicr: u32,
    /// MDEC-out starvation watchdog: when the waiting transfer last saw the decoder idle and
    /// empty, and the decode command that was found unable to fill it.
    starved_since: Option<u64>,
    starved_cmd: Option<u64>,
    starved_reported: bool,
}

impl Dma {
    /// DICR master interrupt flag: forced, or any enabled channel flag with the master enable set.
    fn master_flag(&self) -> bool {
        let d = self.dicr;
        d & (1 << 15) != 0 || (d & (1 << 23) != 0 && (d >> 24) & (d >> 16) & 0x7F != 0)
    }
}

/// CPU read from the DMA registers (MADR / BCR / CHCR per channel, DPCR, DICR).
pub fn read(m: &mut Machine, p: u32) -> u32 {
    let off = p - 0x1F80_1080;
    let n = (off / 0x10) as usize;
    if n < 7 {
        let c = &m.dma.ch[n];
        return match off & 0xF {
            0 => c.madr,
            4 => c.bcr,
            8 => c.chcr,
            _ => 0,
        };
    }
    match p {
        0x1F80_10F0 => m.dma.dpcr,
        0x1F80_10F4 => m.dma.dicr | if m.dma.master_flag() { 1 << 31 } else { 0 },
        _ => 0,
    }
}

/// CPU write to the DMA registers; writing CHCR with the start bit starts the transfer.
pub fn write(m: &mut Machine, p: u32, v: u32) {
    let off = p - 0x1F80_1080;
    let n = (off / 0x10) as usize;
    if n < 7 {
        match off & 0xF {
            0 => m.dma.ch[n].madr = v & 0x00FF_FFFF,
            4 => m.dma.ch[n].bcr = v,
            8 => {
                m.dma.ch[n].chcr = if n == 6 { (v & 0x5100_0000) | 2 } else { v };
                start(m, n);
            }
            _ => {}
        }
        return;
    }
    match p {
        0x1F80_10F0 => m.dma.dpcr = v,
        0x1F80_10F4 => {
            let old = m.dma.master_flag();
            // Bits 24-30 are acknowledged by writing 1; bits 0-5 and 15-23 are R/W.
            let flags = (m.dma.dicr & 0x7F00_0000) & !(v & 0x7F00_0000);
            m.dma.dicr = (v & 0x00FF_803F) | flags;
            if !old && m.dma.master_flag() {
                m.raise(IRQ_DMA);
            }
        }
        _ => {}
    }
}

/// Retry a channel that is still waiting for its device (MDEC out).
pub fn kick(m: &mut Machine, n: usize) {
    start(m, n);
}

/// Run DMA channel `n` (0 MDEC in, 1 MDEC out, 2 GPU, 3 CD-ROM, 4 SPU, 6 OT clear).
fn start(m: &mut Machine, n: usize) {
    let c = m.dma.ch[n];
    if c.chcr & (1 << 24) == 0 {
        return;
    }
    if n == 3 || n == 4 {
        let what = if n == 3 { "cd->ram" } else if c.chcr & 1 != 0 { "ram->spu" } else { "spu->ram" };
        let spu_at = if n == 4 { format!(" spu addr {:05x}", m.spu.transfer_addr()) } else { String::new() };
        crate::diag::event(format!("dma{n} {what} madr {:08x} bcr {:08x} chcr {:08x}{spu_at}", c.madr, c.bcr, c.chcr));
    }
    let sync = (c.chcr >> 9) & 3;
    // Sync mode 0 (immediate block) needs the trigger bit.
    if sync == 0 && c.chcr & (1 << 28) == 0 && n != 6 {
        return;
    }
    if m.dma.dpcr & (8 << (4 * n)) == 0 {
        diag::count(&format!("dma{n} started while disabled in DPCR"));
    }
    let to_ram = c.chcr & 1 == 0;
    let step: i64 = if c.chcr & 2 != 0 { -4 } else { 4 };
    let words = match sync {
        0 => {
            let w = c.bcr & 0xFFFF;
            if w == 0 { 0x10000 } else { w }
        }
        1 => (c.bcr & 0xFFFF) * (c.bcr >> 16),
        _ => 0,
    } as usize;
    // MDEC out streams: move the complete blocks the decoder has produced so far and stay busy
    // until the block count is exhausted (mdec.rs / the end of each DMA0 transfer kick it again).
    if n == 1 && sync == 1 {
        let bs = (c.bcr & 0xFFFF).max(1) as usize;
        let mut ba = (c.bcr >> 16) as usize;
        let mut addr = c.madr & 0x1F_FFFC;
        while ba > 0 && m.mdec.out_available() >= bs {
            for _ in 0..bs {
                let v = mdec::dma_read(m);
                put(m, addr, v);
                addr = (addr as i64 + step) as u32 & 0x1F_FFFC;
            }
            ba -= 1;
        }
        m.dma.ch[1].madr = addr;
        m.dma.ch[1].bcr = (c.bcr & 0xFFFF) | ((ba as u32) << 16);
        if ba > 0 {
            return;
        }
        finish(m, 1);
        return;
    }
    let mut addr = c.madr & 0x1F_FFFC;
    match n {
        2 if sync == 2 => linked_list(m, addr),
        6 => {
            // OT clear: each word points to the previous one, the last is the end marker.
            for i in 0..words {
                let v = if i + 1 == words { 0x00FF_FFFF } else { addr.wrapping_sub(4) & 0x1F_FFFF };
                put(m, addr, v);
                addr = addr.wrapping_sub(4) & 0x1F_FFFC;
            }
        }
        _ => {
            for _ in 0..words {
                if to_ram {
                    let v = match n {
                        1 => mdec::dma_read(m),
                        2 => gpu::read_data(m),
                        3 => cdrom::dma_read(m),
                        4 => spu::dma_read(m),
                        _ => 0,
                    };
                    put(m, addr, v);
                } else {
                    let v = get(m, addr);
                    match n {
                        0 => mdec::dma_write(m, v),
                        2 => gpu::write_gp0(m, v),
                        4 => spu::dma_write(m, v),
                        _ => {}
                    }
                }
                addr = (addr as i64 + step) as u32 & 0x1F_FFFC;
            }
            if sync == 1 {
                m.dma.ch[n].madr = addr;
                m.dma.ch[n].bcr &= 0xFFFF;
            }
        }
    }
    finish(m, n);
    if n == 0 {
        // Decode what this transfer brought, then feed a waiting MDEC-out transfer.
        let more = mdec::input_done(m);
        if more || m.mdec_kick {
            m.mdec_kick = false;
            start(m, 1);
        }
    }
}

/// MDEC-out watchdog (called from `service`). A DMA1 transfer that waits while the decoder is idle
/// with nothing left to output can never finish; on the console that only happens with corrupt
/// movie data. Rather than freeze the game, after 100 ms the rest of the transfer is filled with
/// black and completed (further transfers against the same decode command after 5 ms). The
/// first time, the decoder state and RAM are saved for diagnosis (t3_mdec_input.bin,
/// t3_ram.bin) and the details logged.
pub fn update(m: &mut Machine, now: u64) {
    let c = m.dma.ch[1];
    let waiting = c.chcr & (1 << 24) != 0 && (c.chcr >> 9) & 3 == 1 && (c.bcr >> 16) != 0;
    if !waiting || !m.mdec.starved() {
        m.dma.starved_since = None;
        return;
    }
    let since = *m.dma.starved_since.get_or_insert(now);
    let same_cmd = m.dma.starved_cmd == Some(m.mdec.commands);
    let limit = if same_cmd { crate::CPU_HZ / 200 } else { crate::CPU_HZ / 10 };
    if now - since < limit {
        return;
    }
    m.dma.starved_since = None;
    m.dma.starved_cmd = Some(m.mdec.commands);
    diag::count("mdec-out transfer starved (filled with black)");
    if !m.dma.starved_reported {
        m.dma.starved_reported = true;
        report_starvation(m);
    }
    let bs = (c.bcr & 0xFFFF).max(1);
    let words = bs * (c.bcr >> 16);
    let step: i64 = if c.chcr & 2 != 0 { -4 } else { 4 };
    let mut addr = c.madr & 0x1F_FFFC;
    for _ in 0..words {
        put(m, addr, 0);
        addr = (addr as i64 + step) as u32 & 0x1F_FFFC;
    }
    m.dma.ch[1].madr = addr;
    m.dma.ch[1].bcr = c.bcr & 0xFFFF;
    finish(m, 1);
}

/// Diagnostics: a transfer asked for more MDEC data than was decoded.
fn report_starvation(m: &mut Machine) {
    let c = m.dma.ch[1];
    let (cmd, hw, pos) = m.mdec.snapshot();
    let around: Vec<String> = hw[pos.saturating_sub(8)..(pos + 8).min(hw.len())].iter().map(|h| format!("{h:04x}")).collect();
    diag::log(format!(
        "mdec starved: dma1 madr {:08x} bcr {:08x} waiting; command {cmd:08x} ({} commands) decoded {} macroblocks,          parse stopped at halfword {pos} of {} [{}]; dma0 madr {:08x} bcr {:08x}",
        c.madr,
        c.bcr,
        m.mdec.commands,
        m.mdec.cmd_macroblocks,
        hw.len(),
        around.join(" "),
        m.dma.ch[0].madr,
        m.dma.ch[0].bcr,
    ));
    let bytes: Vec<u8> = hw.iter().flat_map(|h| h.to_le_bytes()).collect();
    let _ = std::fs::write("t3_mdec_input.bin", bytes);
    let _ = std::fs::write("t3_ram.bin", &m.ram[..]);
}

/// GPU linked-list DMA (ordering tables): send each packet's words to GP0 until the end marker.
fn linked_list(m: &mut Machine, mut addr: u32) {
    let mut guard = 0;
    loop {
        let header = get(m, addr);
        let count = header >> 24;
        for i in 0..count {
            let w = get(m, (addr + 4 * (i + 1)) & 0x1F_FFFC);
            gpu::write_gp0(m, w);
        }
        guard += 1;
        if header & 0x80_0000 != 0 || guard > 0x10_0000 {
            break;
        }
        addr = header & 0x1F_FFFC;
    }
    m.dma.ch[2].madr = 0x00FF_FFFF;
}

/// Transfer done: clear the busy bit, set the channel's DICR flag and raise IRQ3 if enabled.
fn finish(m: &mut Machine, n: usize) {
    m.dma.ch[n].chcr &= !((1 << 24) | (1 << 28));
    let old = m.dma.master_flag();
    if m.dma.dicr & (1 << (16 + n)) != 0 {
        m.dma.dicr |= 1 << (24 + n);
    }
    if !old && m.dma.master_flag() {
        m.raise(IRQ_DMA);
    }
}

#[inline]
fn get(m: &Machine, a: u32) -> u32 {
    let a = (a & 0x1F_FFFC) as usize;
    u32::from_le_bytes(m.ram[a..a + 4].try_into().unwrap())
}

#[inline]
fn put(m: &mut Machine, a: u32, v: u32) {
    let a = (a & 0x1F_FFFC) as usize;
    m.ram[a..a + 4].copy_from_slice(&v.to_le_bytes());
}
