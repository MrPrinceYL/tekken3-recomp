//! MDEC (I/O 0x1F801820 command/data, 0x1F801824 status/control): the macroblock decoder used
//! for STR movies. Run-length coded DCT blocks are dequantised, inverse transformed with the
//! game's scale table and converted from YCbCr to 15/24-bit RGB (or 4/8-bit mono). Data arrives
//! through DMA0 and the result leaves through DMA1.
//!
//! Like the hardware, decoding streams: every complete macroblock in the data received so far is
//! decoded at once (after each DMA0 transfer and at the end of the command), and DMA1 moves out
//! whatever has been produced, staying busy until its whole block count has been delivered.

use crate::{dma, Machine};
use std::collections::VecDeque;

const ZIGZAG: [usize; 64] = [
    0, 1, 8, 16, 9, 2, 3, 10, 17, 24, 32, 25, 18, 11, 4, 5, 12, 19, 26, 33, 40, 48, 41, 34, 27, 20, 13, 6, 7, 14, 21,
    28, 35, 42, 49, 56, 57, 50, 43, 36, 29, 22, 15, 23, 30, 37, 44, 51, 58, 59, 52, 45, 38, 31, 39, 46, 53, 60, 61,
    54, 47, 55, 62, 63,
];

pub struct Mdec {
    cmd: u32,
    remaining: u32,
    input: Vec<u32>,
    /// Decode command: run-length halfwords received and the parse position.
    hw: Vec<u16>,
    pos: usize,
    out: VecDeque<u32>,
    qt_y: [u8; 64],
    qt_c: [u8; 64],
    scale: [i16; 64],
    control: u32,
    pub macroblocks: u64,
    pub words_in: u64,
    pub words_out: u64,
    pub commands: u64,
    /// Macroblocks decoded by the current (latest) command.
    pub cmd_macroblocks: u64,
}

impl Mdec {
    /// MDEC in its reset state (default quantisation and IDCT tables).
    pub fn new() -> Self {
        Mdec {
            cmd: 0,
            remaining: 0,
            input: Vec::new(),
            hw: Vec::new(),
            pos: 0,
            out: VecDeque::new(),
            qt_y: [1; 64],
            qt_c: [1; 64],
            scale: [0; 64],
            control: 0,
            macroblocks: 0,
            words_in: 0,
            words_out: 0,
            commands: 0,
            cmd_macroblocks: 0,
        }
    }

    #[cfg(test)]
    pub(crate) fn test_write(&mut self, v: u32) -> bool {
        self.write(v)
    }

    /// Idle with nothing left to hand out: a waiting MDEC-out transfer can't make progress.
    pub fn starved(&self) -> bool {
        self.remaining == 0 && self.out.is_empty()
    }

    /// The current command's word, received run-length halfwords and parse position.
    pub fn snapshot(&self) -> (u32, &[u16], usize) {
        (self.cmd, &self.hw, self.pos)
    }

    /// Words of decoded output waiting to be read.
    pub fn out_available(&self) -> usize {
        self.out.len()
    }

    /// MDEC status register (0x1F801824): FIFO states, busy, current block, output depth.
    pub fn status(&self) -> u32 {
        let mut s = 0u32;
        s |= (self.out.is_empty() as u32) << 31;
        s |= ((self.remaining > 0) as u32) << 29;
        s |= ((self.control >> 30 & 1 != 0 && self.remaining > 0) as u32) << 28;
        s |= ((self.control >> 29 & 1 != 0 && !self.out.is_empty()) as u32) << 27;
        s |= ((self.cmd >> 27) & 3) << 25;
        s |= ((self.cmd >> 26) & 1) << 24;
        s |= ((self.cmd >> 25) & 1) << 23;
        s |= self.remaining.wrapping_sub(1) & 0xFFFF;
        s
    }

    /// Command/data word. Returns true when new output may be available.
    fn write(&mut self, v: u32) -> bool {
        if self.remaining == 0 {
            self.cmd = v;
            self.commands += 1;
            self.cmd_macroblocks = 0;
            self.input.clear();
            self.hw.clear();
            self.pos = 0;
            self.remaining = match v >> 29 {
                1 => v & 0xFFFF,
                2 => if v & 1 != 0 { 32 } else { 16 },
                3 => 32,
                _ => 0,
            };
            return false;
        }
        self.remaining -= 1;
        self.words_in += 1;
        if self.cmd >> 29 == 1 {
            self.hw.push(v as u16);
            self.hw.push((v >> 16) as u16);
            if self.remaining == 0 {
                self.decode();
                return true;
            }
            return false;
        }
        self.input.push(v);
        if self.remaining > 0 {
            return false;
        }
        match self.cmd >> 29 {
            2 => {
                let bytes: Vec<u8> = self.input.iter().flat_map(|w| w.to_le_bytes()).collect();
                self.qt_y.copy_from_slice(&bytes[..64]);
                if self.cmd & 1 != 0 {
                    self.qt_c.copy_from_slice(&bytes[64..128]);
                }
            }
            3 => {
                for (i, w) in self.input.iter().enumerate() {
                    self.scale[2 * i] = *w as i16;
                    self.scale[2 * i + 1] = (*w >> 16) as i16;
                }
            }
            _ => {}
        }
        false
    }

    /// Decode what has arrived so far (called at the end of each DMA0 transfer).
    pub fn flush(&mut self) -> bool {
        if self.cmd >> 29 == 1 && self.remaining > 0 {
            let before = self.out.len();
            self.decode();
            return self.out.len() != before;
        }
        false
    }

    /// Inverse DCT of one 8x8 block with the scale table, as the hardware computes it.
    fn idct(&self, blk: &mut [i32; 64]) {
        let mut tmp = [0i64; 64];
        let mut src: [i64; 64] = std::array::from_fn(|i| blk[i] as i64);
        for _pass in 0..2 {
            for x in 0..8 {
                for y in 0..8 {
                    let mut sum = 0i64;
                    for z in 0..8 {
                        sum += src[y + z * 8] * ((self.scale[x + z * 8] as i64) >> 3);
                    }
                    tmp[x + y * 8] = (sum + 0xFFF) >> 13;
                }
            }
            std::mem::swap(&mut src, &mut tmp);
        }
        for i in 0..64 {
            blk[i] = src[i] as i32;
        }
    }

    /// Decode one block from the halfword stream at `pos`. Returns false if the data ends
    /// before the block does (nothing is consumed then).
    fn block(&self, hw: &[u16], pos: &mut usize, qt: &[u8; 64], blk: &mut [i32; 64]) -> bool {
        let start = *pos;
        *blk = [0; 64];
        // Skip padding (FE00h) before the DC value.
        while *pos < hw.len() && hw[*pos] == 0xFE00 {
            *pos += 1;
        }
        if *pos >= hw.len() {
            *pos = start;
            return false;
        }
        let s10 = |n: u16| ((n as i32) << 22) >> 22;
        let n = hw[*pos];
        *pos += 1;
        let q = ((n >> 10) & 0x3F) as i32;
        let mut k = 0usize;
        let mut cur = n;
        let mut val = s10(n) * qt[0] as i32;
        loop {
            if q == 0 {
                val = s10(cur) * 2;
            }
            val = val.clamp(-0x400, 0x3FF);
            if q > 0 {
                blk[ZIGZAG[k]] = val;
            } else {
                blk[k] = val;
            }
            if *pos >= hw.len() {
                // The end code has not arrived yet.
                *pos = start;
                return false;
            }
            cur = hw[*pos];
            *pos += 1;
            k += ((cur >> 10) & 0x3F) as usize + 1;
            if k > 63 {
                break;
            }
            val = (s10(cur) * qt[k] as i32 * q + 4) / 8;
        }
        self.idct(blk);
        true
    }

    /// Run the current command: decode run-level coded macroblocks into 15/24-bit RGB (or 4/8-bit
    /// monochrome) pixels, or load the quantisation / scale tables.
    fn decode(&mut self) {
        let hw = std::mem::take(&mut self.hw);
        let mut pos = self.pos;
        let depth = (self.cmd >> 27) & 3;
        let signed = self.cmd & (1 << 26) != 0;
        let bit15 = if self.cmd & (1 << 25) != 0 { 0x8000u32 } else { 0 };
        let mut bytes: Vec<u8> = Vec::new();
        let (qy, qc) = (self.qt_y, self.qt_c);
        if depth >= 2 {
            loop {
                let mark = pos;
                let mut cr = [0i32; 64];
                let mut cb = [0i32; 64];
                let mut y = [[0i32; 64]; 4];
                let mut ok = self.block(&hw, &mut pos, &qc, &mut cr) && self.block(&hw, &mut pos, &qc, &mut cb);
                for b in y.iter_mut() {
                    ok = ok && self.block(&hw, &mut pos, &qy, b);
                }
                if !ok {
                    pos = mark;
                    break;
                }
                self.macroblocks += 1;
                self.cmd_macroblocks += 1;
                let mut px = [[0u8; 3]; 256];
                for (bi, yb) in y.iter().enumerate() {
                    let (xx, yy) = ((bi & 1) * 8, (bi >> 1) * 8);
                    for py in 0..8 {
                        for pxi in 0..8 {
                            let ci = (xx + pxi) / 2 + ((yy + py) / 2) * 8;
                            let (r0, b0) = (cr[ci] as f32, cb[ci] as f32);
                            let g = (-0.3437 * b0 + -0.7143 * r0) as i32;
                            let r = (1.402 * r0) as i32;
                            let b = (1.772 * b0) as i32;
                            let yv = yb[pxi + py * 8];
                            let c = |v: i32| -> u8 {
                                let v = v.clamp(-128, 127);
                                (if signed { v } else { v + 128 }) as u8
                            };
                            px[(xx + pxi) + (yy + py) * 16] = [c(yv + r), c(yv + g), c(yv + b)];
                        }
                    }
                }
                if depth == 2 {
                    for p in px.iter() {
                        bytes.extend_from_slice(p);
                    }
                } else {
                    for p in px.iter() {
                        let v = ((p[0] as u32) >> 3) | (((p[1] as u32) >> 3) << 5) | (((p[2] as u32) >> 3) << 10) | bit15;
                        bytes.extend_from_slice(&(v as u16).to_le_bytes());
                    }
                }
            }
        } else {
            // Monochrome: one Y block per 8x8.
            let mut blk = [0i32; 64];
            while self.block(&hw, &mut pos, &qy, &mut blk) {
                self.macroblocks += 1;
                self.cmd_macroblocks += 1;
                let vals: Vec<u8> = blk
                    .iter()
                    .map(|&v| {
                        let v = v.clamp(-128, 127);
                        (if signed { v } else { v + 128 }) as u8
                    })
                    .collect();
                if depth == 1 {
                    bytes.extend_from_slice(&vals);
                } else {
                    for pair in vals.chunks(2) {
                        bytes.push((pair[0] >> 4) | (pair[1] & 0xF0));
                    }
                }
            }
        }
        self.hw = hw;
        self.pos = pos;
        // Every macroblock is a whole number of words (24-bit: 192, 15-bit: 128, mono: 16/8).
        for w in bytes.chunks_exact(4) {
            self.out.push_back(u32::from_le_bytes([w[0], w[1], w[2], w[3]]));
        }
    }
}

impl Default for Mdec {
    /// Same as `Mdec::new`.
    fn default() -> Self {
        Self::new()
    }
}

/// CPU write to the MDEC command / data register (0x1F801820).
pub fn write_command(m: &mut Machine, v: u32) {
    if m.mdec.write(v) {
        dma::kick(m, 1);
    }
}

/// CPU write to the MDEC control register (0x1F801824): reset, DMA enables.
pub fn write_control(m: &mut Machine, v: u32) {
    if v & 0x8000_0000 != 0 {
        m.mdec.remaining = 0;
        m.mdec.out.clear();
        m.mdec.input.clear();
        m.mdec.hw.clear();
        m.mdec.pos = 0;
        m.mdec.cmd = 0;
    }
    m.mdec.control = v;
}

/// CPU read of MDEC output (0x1F801820).
pub fn read_data(m: &mut Machine) -> u32 {
    m.mdec.words_out += 1;
    m.mdec.out.pop_front().unwrap_or(0)
}

/// DMA0 to the MDEC: one word of command data.
pub fn dma_write(m: &mut Machine, v: u32) {
    if m.mdec.write(v) {
        // Output becomes available after the DMA0 transfer finishes (dma.rs runs DMA1 then).
        m.mdec_kick = true;
    }
}

/// DMA1 from the MDEC: one word of decoded output.
pub fn dma_read(m: &mut Machine) -> u32 {
    m.mdec.words_out += 1;
    m.mdec.out.pop_front().unwrap_or(0)
}

/// End of a DMA0 transfer: decode the complete macroblocks received so far.
pub fn input_done(m: &mut Machine) -> bool {
    m.mdec.flush()
}
