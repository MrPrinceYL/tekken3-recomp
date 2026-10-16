//! Controller port (SIO0, I/O 0x1F801040..0x1F80104F) with a digital pad (SCPH-1080) on each
//! port that has a controller.
//!
//! The game's pad driver (libtap) bit-bangs the protocol itself from its vertical blank handler:
//! it sends 01h 42h 00h 00h 00h and, after each byte, polls I_STAT for the controller's /ACK
//! interrupt (IRQ7) a bounded number of times. The ACK must therefore arrive after the driver has
//! cleared I_STAT and seen the received byte, not at the instant of the write: it is raised on the
//! second read of JOY_STAT / I_STAT after the byte (a register-access clock instead of wall time,
//! so it is deterministic however fast the host runs). Memory cards are not on this bus: the HLE
//! BIOS handles them (kernel.rs / memcard.rs).

use crate::pad::PadShared;
use crate::{Machine, IRQ_SIO};
use std::collections::VecDeque;
use std::sync::Arc;

pub struct Sio {
    pad: Arc<PadShared>,
    rx: VecDeque<u8>,
    ctrl: u16,
    mode: u16,
    baud: u16,
    irq: bool,
    /// Byte index within the current transaction (reset on deselect), and the device addressed.
    step: usize,
    device: u8,
    latched: [u8; 2],
    ack_countdown: u32,
    pub polls: u64,
}

impl Sio {
    /// Controller port with the shared pad state; nothing selected.
    pub fn new(pad: Arc<PadShared>) -> Self {
        Sio { pad, rx: VecDeque::new(), ctrl: 0, mode: 0, baud: 0, irq: false, step: 0, device: 0, latched: [0xFF; 2], ack_countdown: 0, polls: 0 }
    }

    /// JOY_STAT: TX ready / finished, RX FIFO not empty, interrupt request.
    fn stat(&self) -> u32 {
        let mut s = 0x5u32; // TX ready, TX finished
        s |= (!self.rx.is_empty() as u32) << 1;
        s |= (self.irq as u32) << 9;
        s
    }

    /// Exchange one byte with the selected device; returns (response, acknowledges).
    fn exchange(&mut self, b: u8) -> (u8, bool) {
        let port = ((self.ctrl >> 13) & 1) as usize;
        let (buttons, connected) = self.pad.get(port);
        let step = self.step;
        self.step += 1;
        if step == 0 {
            self.device = b;
            if b == 0x01 && connected {
                let inv = !buttons;
                self.latched = [inv as u8, (inv >> 8) as u8];
                self.polls += 1;
                return (0xFF, true);
            }
            return (0xFF, false);
        }
        if self.device != 0x01 || !connected {
            return (0xFF, false);
        }
        match step {
            1 => (0x41, true),
            2 => (0x5A, true),
            3 => (self.latched[0], true),
            4 => (self.latched[1], false),
            _ => (0xFF, false),
        }
    }
}

/// Count down a pending /ACK and raise IRQ7 when it lands.
fn tick_ack(m: &mut Machine) {
    if m.sio.ack_countdown > 0 {
        m.sio.ack_countdown -= 1;
        if m.sio.ack_countdown == 0 {
            m.sio.irq = true;
            m.raise(IRQ_SIO);
        }
    }
}

/// Called before I_STAT reads: lets a pending controller ACK land.
pub fn on_istat_read(m: &mut Machine) {
    tick_ack(m);
}

/// CPU read from the controller port registers (data, status, mode, control, baud).
pub fn read(m: &mut Machine, p: u32, size: usize) -> u32 {
    match p & 0xF {
        0x0 => {
            let mut v = 0u32;
            for i in 0..size.min(4) {
                v |= (m.sio.rx.pop_front().unwrap_or(0xFF) as u32) << (8 * i);
            }
            v
        }
        0x4 => {
            tick_ack(m);
            m.sio.stat()
        }
        0x8 => m.sio.mode as u32,
        0xA => m.sio.ctrl as u32,
        0xE => m.sio.baud as u32,
        _ => 0,
    }
}

/// CPU write to the controller port registers: a data write exchanges one byte with the selected pad.
pub fn write(m: &mut Machine, p: u32, _size: usize, v: u32) {
    let s = &mut m.sio;
    match p & 0xF {
        0x0 => {
            if s.ctrl & 2 != 0 {
                let (resp, ack) = s.exchange(v as u8);
                s.rx.push_back(resp);
                while s.rx.len() > 8 {
                    s.rx.pop_front();
                }
                if ack && s.ctrl & 0x1000 != 0 {
                    s.ack_countdown = 2;
                }
            } else {
                s.rx.push_back(0xFF);
            }
        }
        0x8 => s.mode = v as u16,
        0xA => {
            let v = v as u16;
            if v & 0x40 != 0 {
                // Reset.
                s.rx.clear();
                s.irq = false;
                s.step = 0;
                s.ack_countdown = 0;
            }
            if v & 0x10 != 0 {
                s.irq = false;
            }
            if v & 2 == 0 || (v ^ s.ctrl) & 0x2000 != 0 {
                // Deselect (or another port): a new transaction starts.
                s.step = 0;
            }
            s.ctrl = v & !0x50;
        }
        0xE => s.baud = v as u16,
        _ => {}
    }
}

/// Nothing to do per service: the port is clocked by register accesses (see the module docs).
pub fn update(_m: &mut Machine, _now: u64) {}
