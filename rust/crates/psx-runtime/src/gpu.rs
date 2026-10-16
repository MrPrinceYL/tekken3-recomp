//! GPU (I/O 0x1F801810 GP0/GPUREAD, 0x1F801814 GP1/GPUSTAT).
//!
//! GP0 words are assembled into commands and executed at once by the software rasterizer
//! (raster.rs) on the 1024x512 16-bit VRAM, as the real GPU draws them. At every vertical blank
//! the display area is converted to RGBA8 and handed to the front end ([`FrameShared`]).

use crate::{raster, Machine, CYCLES_PER_FRAME, CYCLES_PER_LINE};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};

/// Debug view (F3 in the app): publish the whole 1024x512 VRAM instead of the display area.
pub static SHOW_VRAM: AtomicBool = AtomicBool::new(false);
use std::sync::Mutex;

pub const VRAM_W: usize = 1024;
pub const VRAM_H: usize = 512;

/// A finished frame for the front end.
#[derive(Clone, Default)]
pub struct Frame {
    pub width: u32,
    pub height: u32,
    /// RGBA8, width*height*4 bytes.
    pub rgba: Vec<u8>,
    /// Display disabled (screen black).
    pub blank: bool,
}

#[derive(Default)]
pub struct FrameShared {
    frame: Mutex<Frame>,
    count: AtomicU64,
    /// Frames the game itself produced: display-buffer flips (GP1(05h) with a new start).
    flips: AtomicU64,
}

impl FrameShared {
    /// Frames published so far (one per vertical blank).
    pub fn count(&self) -> u64 {
        self.count.load(Relaxed)
    }
    /// Display-buffer flips the game made (new display start address): its real frame rate.
    pub fn flips(&self) -> u64 {
        self.flips.load(Relaxed)
    }
    /// A copy of the newest published frame.
    pub fn latest(&self) -> Frame {
        self.frame.lock().unwrap().clone()
    }
    /// Copy the latest frame into `out` if it is newer than `seen`; returns the frame count.
    pub fn take_if_new(&self, seen: u64, out: &mut Frame) -> u64 {
        let n = self.count();
        if n != seen {
            let f = self.frame.lock().unwrap();
            out.width = f.width;
            out.height = f.height;
            out.blank = f.blank;
            out.rgba.clear();
            out.rgba.extend_from_slice(&f.rgba);
        }
        n
    }
    /// Hand a finished frame to the front end (swap, no copy).
    fn publish(&self, f: &mut Frame) {
        std::mem::swap(&mut *self.frame.lock().unwrap(), f);
        self.count.fetch_add(1, Relaxed);
    }
}

/// Drawing state shared by all primitives (GP0 E1h-E6h).
#[derive(Clone, Copy, Default)]
pub struct DrawEnv {
    pub texpage: u32, // E1 bits 0-13 (page x/y, semi mode, depth, dither, draw-to-display, disable, flips)
    pub tw_mask_x: u32,
    pub tw_mask_y: u32,
    pub tw_off_x: u32,
    pub tw_off_y: u32,
    pub area_x1: i32,
    pub area_y1: i32,
    pub area_x2: i32,
    pub area_y2: i32,
    pub off_x: i32,
    pub off_y: i32,
    pub set_mask: bool,
    pub check_mask: bool,
}

#[derive(PartialEq, Clone, Copy)]
enum Transfer {
    None,
    /// CPU -> VRAM: (x, y, w, h, pixels written so far).
    ToVram(u32, u32, u32, u32, u32),
    /// VRAM -> CPU.
    FromVram(u32, u32, u32, u32, u32),
}

pub struct Gpu {
    pub vram: Vec<u16>,
    pub env: DrawEnv,
    fifo: Vec<u32>,
    need: usize,
    polyline: bool,
    transfer: Transfer,
    read_latch: u32,
    // GP1 state.
    pub display_x: u32,
    pub display_y: u32,
    pub h_start: u32,
    pub h_end: u32,
    pub v_start: u32,
    pub v_end: u32,
    pub mode: u32, // GP1(08h) bits 0-6 (+ bit 7 at 6)
    pub display_off: bool,
    pub dma_dir: u32,
    pub irq: bool,
    field: bool,
    /// Device time of the last vertical blank (scanline position for GPUSTAT bit 31).
    vblank_at: u64,
    out: Frame,
    pub prims: u64,
    pub flips: u64,
    /// GP0 commands executed, by command byte (diagnostics).
    pub cmd_counts: [u64; 256],
}

impl Gpu {
    /// GPU in its power-on state: 1 MiB VRAM cleared, display off, 256x240 NTSC.
    pub fn new() -> Self {
        let mut g = Gpu {
            vram: vec![0; VRAM_W * VRAM_H],
            env: DrawEnv::default(),
            fifo: Vec::with_capacity(16),
            need: 0,
            polyline: false,
            transfer: Transfer::None,
            read_latch: 0,
            display_x: 0,
            display_y: 0,
            h_start: 0x200,
            h_end: 0xC00,
            v_start: 0x10,
            v_end: 0x100,
            mode: 0,
            display_off: true,
            dma_dir: 0,
            irq: false,
            field: false,
            vblank_at: 0,
            out: Frame::default(),
            prims: 0,
            flips: 0,
            cmd_counts: [0; 256],
        };
        g.reset();
        g
    }

    /// GP1(00h) reset: drawing and display state back to defaults (VRAM is kept).
    fn reset(&mut self) {
        self.env = DrawEnv { area_x2: 0, area_y2: 0, ..DrawEnv::default() };
        self.fifo.clear();
        self.need = 0;
        self.transfer = Transfer::None;
        self.display_off = true;
        self.dma_dir = 0;
        self.irq = false;
        self.display_x = 0;
        self.display_y = 0;
        self.h_start = 0x200;
        self.h_end = 0xC00;
        self.v_start = 0x10;
        self.v_end = 0x100;
        self.mode = 0;
    }

    /// Horizontal display resolution from the display mode (256 / 320 / 368 / 512 / 640).
    pub fn hres(&self) -> u32 {
        if self.mode & 0x40 != 0 {
            368
        } else {
            [256, 320, 512, 640][(self.mode & 3) as usize]
        }
    }

    /// Dot clock divider for root counter 0.
    pub fn dot_div(&self) -> u32 {
        if self.mode & 0x40 != 0 { 7 } else { [10, 8, 5, 4][(self.mode & 3) as usize] }
    }

    /// True if the display is 480-line interlaced.
    pub fn interlaced(&self) -> bool {
        self.mode & 0x20 != 0 && self.mode & 4 != 0
    }

    /// GPUSTAT (0x1F801814): ready bits, DMA direction, display mode, interlace field ...
    pub fn status(&self, now: u64) -> u32 {
        let e = &self.env;
        let mut s = e.texpage & 0x7FF;
        s |= ((e.texpage >> 11) & 1) << 15; // texture disable
        s |= (e.set_mask as u32) << 11;
        s |= (e.check_mask as u32) << 12;
        // Interlace field: odd/even frame for interlaced modes, always 1 otherwise.
        s |= (if self.interlaced() { self.field as u32 } else { 1 }) << 13;
        s |= ((self.mode >> 6) & 1) << 16;
        s |= (self.mode & 3) << 17;
        s |= ((self.mode >> 2) & 1) << 19;
        s |= ((self.mode >> 3) & 1) << 20;
        s |= ((self.mode >> 4) & 1) << 21;
        s |= ((self.mode >> 5) & 1) << 22;
        s |= (self.display_off as u32) << 23;
        s |= (self.irq as u32) << 24;
        let to_cpu = matches!(self.transfer, Transfer::FromVram(..));
        let ready_cmd = 1u32;
        let ready_send = to_cpu as u32;
        let ready_dma = 1u32;
        s |= ready_cmd << 26 | ready_send << 27 | ready_dma << 28;
        s |= (self.dma_dir & 3) << 29;
        s |= match self.dma_dir {
            0 => 0,
            1 => 1,
            2 => ready_dma,
            _ => ready_send,
        } << 25;
        // Bit 31: odd line being drawn (non-interlaced: alternates per scanline; interlaced: the
        // odd field), 0 during vertical blank. Lines 240..262 are the blanking period, which
        // starts at the vertical blank interrupt.
        let since = now.saturating_sub(self.vblank_at) % CYCLES_PER_FRAME;
        let line = (240 + since / CYCLES_PER_LINE) % 263;
        let odd = if self.interlaced() { self.field } else { line & 1 == 1 };
        let in_vblank = line >= 240;
        s |= ((odd && !in_vblank) as u32) << 31;
        s
    }

    /// Vertical blank: build the displayed frame from VRAM and publish it for the front end.
    pub fn vblank(&mut self, frames: &FrameShared, now: u64) {
        self.vblank_at = now;
        self.field = !self.field;
        self.build_frame();
        frames.flips.store(self.flips, Relaxed);
        frames.publish(&mut self.out);
    }

    /// Convert the display area of VRAM (15- or 24-bit) into an RGBA frame.
    fn build_frame(&mut self) {
        if SHOW_VRAM.load(Relaxed) {
            self.out.width = VRAM_W as u32;
            self.out.height = VRAM_H as u32;
            self.out.blank = false;
            self.out.rgba.resize(VRAM_W * VRAM_H * 4, 0);
            for (px, d) in self.vram.iter().zip(self.out.rgba.chunks_exact_mut(4)) {
                let c5 = |v: u16| -> u8 {
                    let v = (v & 31) as u8;
                    (v << 3) | (v >> 2)
                };
                d.copy_from_slice(&[c5(*px), c5(*px >> 5), c5(*px >> 10), 255]);
            }
            return;
        }
        let w = self.hres();
        // Visible lines from the vertical display range (doubled when interlaced).
        let lines = self.v_end.saturating_sub(self.v_start).clamp(1, 256);
        let h = if self.interlaced() { (lines * 2).min(480) } else { lines.min(240) };
        let (w, h) = (w.max(1), h.max(1));
        self.out.width = w;
        self.out.height = h;
        self.out.blank = self.display_off;
        self.out.rgba.resize((w * h * 4) as usize, 0);
        if self.display_off {
            self.out.rgba.fill(0);
            for px in self.out.rgba.chunks_exact_mut(4) {
                px[3] = 255;
            }
            return;
        }
        let depth24 = self.mode & 0x10 != 0;
        let (dx, dy) = (self.display_x as usize, self.display_y as usize);
        let vram = &self.vram;
        for y in 0..h as usize {
            let vy = (dy + y) & (VRAM_H - 1);
            let row = &mut self.out.rgba[y * w as usize * 4..(y + 1) * w as usize * 4];
            if depth24 {
                let base = vy * VRAM_W;
                for x in 0..w as usize {
                    let bo = dx * 2 + x * 3;
                    let byte = |b: usize| -> u8 {
                        let px = vram[base + ((b / 2) & (VRAM_W - 1))];
                        if b & 1 == 0 { px as u8 } else { (px >> 8) as u8 }
                    };
                    row[x * 4] = byte(bo);
                    row[x * 4 + 1] = byte(bo + 1);
                    row[x * 4 + 2] = byte(bo + 2);
                    row[x * 4 + 3] = 255;
                }
            } else {
                for x in 0..w as usize {
                    let px = vram[vy * VRAM_W + ((dx + x) & (VRAM_W - 1))];
                    let c5 = |v: u16| -> u8 {
                        let v = (v & 31) as u8;
                        (v << 3) | (v >> 2)
                    };
                    row[x * 4] = c5(px);
                    row[x * 4 + 1] = c5(px >> 5);
                    row[x * 4 + 2] = c5(px >> 10);
                    row[x * 4 + 3] = 255;
                }
            }
        }
    }

    /// Collect one GP0 word; runs the command once all its words (or a polyline's terminator) arrived.
    /// Returns true while a VRAM upload is still consuming data words.
    fn gp0(&mut self, w: u32) -> bool {
        // Returns true when a GPU IRQ was requested.
        if let Transfer::ToVram(x, y, tw, th, n) = self.transfer {
            let total = tw * th;
            let mut n = n;
            for half in [w & 0xFFFF, w >> 16] {
                if n < total {
                    let px = x + n % tw;
                    let py = y + n / tw;
                    raster::put_vram(self, px, py, half as u16);
                    n += 1;
                }
            }
            self.transfer = if n >= total { Transfer::None } else { Transfer::ToVram(x, y, tw, th, n) };
            return false;
        }
        if self.need == 0 {
            self.fifo.clear();
            let cmd = w >> 24;
            self.need = cmd_len(cmd);
            self.polyline = (0x48..=0x4F).contains(&cmd) || (0x58..=0x5F).contains(&cmd);
        }
        self.fifo.push(w);
        if self.polyline {
            // Vertex words of a polyline end with the 0x5xxx5xxx terminator.
            let gouraud = self.fifo[0] & 0x1000_0000 != 0;
            let n = self.fifo.len();
            let is_vertex_pos = if gouraud { n >= 3 && n % 2 == 1 } else { n >= 2 };
            if n > 2 && is_vertex_pos && w & 0xF000_F000 == 0x5000_5000 {
                self.fifo.pop();
                let words = std::mem::take(&mut self.fifo);
                raster::polyline(self, &words);
                self.fifo = words;
                self.need = 0;
                self.polyline = false;
            } else if n > 256 {
                self.need = 0;
                self.polyline = false;
            }
            return false;
        }
        if self.fifo.len() < self.need {
            return false;
        }
        self.need = 0;
        let words = std::mem::take(&mut self.fifo);
        let irq = self.execute(&words);
        self.fifo = words;
        irq
    }

    /// Execute a complete GP0 command: fill, polygons, lines, rectangles, VRAM copies / transfers,
    /// draw mode and drawing area settings. The drawing itself is in raster.rs.
    fn execute(&mut self, f: &[u32]) -> bool {
        let cmd = f[0] >> 24;
        self.cmd_counts[cmd as usize] += 1;
        match cmd {
            0x01 => {}
            0x02 => raster::fill(self, f),
            0x1F => {
                self.irq = true;
                return true;
            }
            0x20..=0x3F => {
                self.prims += 1;
                raster::polygon(self, f)
            }
            0x40..=0x5F => {
                self.prims += 1;
                raster::line(self, f)
            }
            0x60..=0x7F => {
                self.prims += 1;
                raster::rect(self, f)
            }
            0x80..=0x9F => raster::copy(self, f),
            0xA0..=0xBF => {
                let (x, y) = (f[1] & 0x3FF, (f[1] >> 16) & 0x1FF);
                let w = ((f[2] & 0xFFFF).wrapping_sub(1) & 0x3FF) + 1;
                let h = (((f[2] >> 16) & 0xFFFF).wrapping_sub(1) & 0x1FF) + 1;
                self.transfer = Transfer::ToVram(x, y, w, h, 0);
            }
            0xC0..=0xDF => {
                let (x, y) = (f[1] & 0x3FF, (f[1] >> 16) & 0x1FF);
                let w = ((f[2] & 0xFFFF).wrapping_sub(1) & 0x3FF) + 1;
                let h = (((f[2] >> 16) & 0xFFFF).wrapping_sub(1) & 0x1FF) + 1;
                self.transfer = Transfer::FromVram(x, y, w, h, 0);
            }
            0xE1 => self.env.texpage = f[0] & 0x3FFF,
            0xE2 => {
                self.env.tw_mask_x = f[0] & 0x1F;
                self.env.tw_mask_y = (f[0] >> 5) & 0x1F;
                self.env.tw_off_x = (f[0] >> 10) & 0x1F;
                self.env.tw_off_y = (f[0] >> 15) & 0x1F;
            }
            0xE3 => {
                self.env.area_x1 = (f[0] & 0x3FF) as i32;
                self.env.area_y1 = ((f[0] >> 10) & 0x1FF) as i32;
            }
            0xE4 => {
                self.env.area_x2 = (f[0] & 0x3FF) as i32;
                self.env.area_y2 = ((f[0] >> 10) & 0x1FF) as i32;
            }
            0xE5 => {
                self.env.off_x = ((f[0] as i32) << 21) >> 21;
                self.env.off_y = ((f[0] as i32) << 10) >> 21;
            }
            0xE6 => {
                self.env.set_mask = f[0] & 1 != 0;
                self.env.check_mask = f[0] & 2 != 0;
            }
            _ => {}
        }
        false
    }

    /// GPUREAD (0x1F801810): VRAM-to-CPU transfer data or the latched GP1(10h) info value.
    fn read(&mut self) -> u32 {
        if let Transfer::FromVram(x, y, w, h, n) = self.transfer {
            let total = w * h;
            let mut v = 0u32;
            let mut n = n;
            for i in 0..2 {
                if n < total {
                    let px = (x + n % w) as usize & (VRAM_W - 1);
                    let py = (y + n / w) as usize & (VRAM_H - 1);
                    v |= (self.vram[py * VRAM_W + px] as u32) << (16 * i);
                    n += 1;
                }
            }
            self.transfer = if n >= total { Transfer::None } else { Transfer::FromVram(x, y, w, h, n) };
            return v;
        }
        self.read_latch
    }

    /// GP1 display control command: reset, display enable, DMA direction, display area / range / mode,
    /// GPU info.
    fn gp1(&mut self, v: u32) {
        match v >> 24 {
            0x00 => self.reset(),
            0x01 => {
                self.fifo.clear();
                self.need = 0;
                self.polyline = false;
                self.transfer = Transfer::None;
            }
            0x02 => self.irq = false,
            0x03 => self.display_off = v & 1 != 0,
            0x04 => self.dma_dir = v & 3,
            0x05 => {
                let (x, y) = (v & 0x3FE, (v >> 10) & 0x1FF);
                if (x, y) != (self.display_x, self.display_y) {
                    self.flips += 1;
                }
                self.display_x = x;
                self.display_y = y;
            }
            0x06 => {
                self.h_start = v & 0xFFF;
                self.h_end = (v >> 12) & 0xFFF;
            }
            0x07 => {
                self.v_start = v & 0x3FF;
                self.v_end = (v >> 10) & 0x3FF;
            }
            0x08 => self.mode = (v & 0x3F) | ((v >> 6) & 1) << 6 | ((v >> 7) & 1) << 7,
            0x10..=0x1F => {
                let e = &self.env;
                self.read_latch = match v & 7 {
                    2 => e.tw_mask_x | e.tw_mask_y << 5 | e.tw_off_x << 10 | e.tw_off_y << 15,
                    3 => (e.area_x1 as u32) | (e.area_y1 as u32) << 10,
                    4 => (e.area_x2 as u32) | (e.area_y2 as u32) << 10,
                    5 => ((e.off_x as u32) & 0x7FF) | ((e.off_y as u32) & 0x7FF) << 11,
                    7 => 2,
                    _ => self.read_latch,
                };
            }
            _ => {}
        }
    }
}

impl Default for Gpu {
    /// Same as `Gpu::new`.
    fn default() -> Self {
        Self::new()
    }
}

/// Words in a GP0 command (polylines are open-ended and handled separately).
fn cmd_len(cmd: u32) -> usize {
    match cmd {
        0x02 => 3,
        0x20..=0x3F => {
            let verts = if cmd & 8 != 0 { 4 } else { 3 };
            let tex = (cmd & 4 != 0) as usize;
            let gouraud = (cmd & 0x10 != 0) as usize;
            1 + verts * (1 + tex) + gouraud * (verts - 1)
        }
        0x40..=0x5F => {
            if cmd & 8 != 0 {
                usize::MAX // polyline
            } else if cmd & 0x10 != 0 {
                4
            } else {
                3
            }
        }
        0x60..=0x7F => {
            let tex = (cmd & 4 != 0) as usize;
            let var = ((cmd >> 3) & 3 == 0) as usize;
            2 + tex + var
        }
        0x80..=0x9F => 4,
        0xA0..=0xBF | 0xC0..=0xDF => 3,
        _ => 1,
    }
}

/// CPU write to GP0 (0x1F801810).
pub fn write_gp0(m: &mut Machine, v: u32) {
    if m.gpu.gp0(v) {
        m.raise(crate::IRQ_GPU);
    }
}

/// CPU write to GP1 (0x1F801814).
pub fn write_gp1(m: &mut Machine, v: u32) {
    m.gpu.gp1(v);
    m.timers.dot_div = m.gpu.dot_div();
}

/// CPU read from GPUREAD (0x1F801810).
pub fn read_data(m: &mut Machine) -> u32 {
    m.gpu.read()
}
