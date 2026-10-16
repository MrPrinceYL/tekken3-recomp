//! Controller state shared between the Bevy input system and the emulated controller port.

use std::sync::atomic::{AtomicBool, AtomicU16, Ordering::Relaxed};

// Button bits as the pad reports them (active high here; the pad sends them inverted).
pub const SELECT: u16 = 1 << 0;
pub const L3: u16 = 1 << 1;
pub const R3: u16 = 1 << 2;
pub const START: u16 = 1 << 3;
pub const UP: u16 = 1 << 4;
pub const RIGHT: u16 = 1 << 5;
pub const DOWN: u16 = 1 << 6;
pub const LEFT: u16 = 1 << 7;
pub const L2: u16 = 1 << 8;
pub const R2: u16 = 1 << 9;
pub const L1: u16 = 1 << 10;
pub const R1: u16 = 1 << 11;
pub const TRIANGLE: u16 = 1 << 12;
pub const CIRCLE: u16 = 1 << 13;
pub const CROSS: u16 = 1 << 14;
pub const SQUARE: u16 = 1 << 15;

pub struct PadShared {
    pub buttons: [AtomicU16; 2],
    pub connected: [AtomicBool; 2],
}

impl Default for PadShared {
    /// Port 1 connected, port 2 empty, no buttons held.
    fn default() -> Self {
        PadShared {
            buttons: [AtomicU16::new(0), AtomicU16::new(0)],
            connected: [AtomicBool::new(true), AtomicBool::new(false)],
        }
    }
}

impl PadShared {
    /// Set port `port`'s held buttons (bits above) and whether a pad is plugged in.
    pub fn set(&self, port: usize, buttons: u16, connected: bool) {
        self.buttons[port].store(buttons, Relaxed);
        self.connected[port].store(connected, Relaxed);
    }
    /// Held buttons and connected flag of port `port`.
    pub fn get(&self, port: usize) -> (u16, bool) {
        (self.buttons[port].load(Relaxed), self.connected[port].load(Relaxed))
    }
}
