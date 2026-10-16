//! Sony controllers (DualSense, DualSense Edge, DualShock 4; USB and Bluetooth) read directly
//! over HID.
//!
//! Bevy reads gamepads through gilrs, which on Windows uses the system gamepad API. That API
//! reports a DualSense connected over Bluetooth but often delivers none of its input (SDL and
//! Steam read Sony pads over HID for the same reason). This module opens the pads' HID
//! interfaces itself, decodes their input reports on a background thread and offers the result
//! with Bevy's button and axis names, so bindings (controls.json, F2) work unchanged.
//!
//! Report layouts (after the report id byte):
//! - DualSense USB 0x01 (64 bytes) and Bluetooth 0x31 (one extra byte first): sticks LX LY RX RY,
//!   triggers L2 R2, a counter, then buttons b0 b1 b2.
//! - DualSense Bluetooth 0x01 "simple" report (10 bytes) and DualShock 4 USB / Bluetooth 0x01:
//!   sticks LX LY RX RY, buttons b0 b1 b2, triggers L2 R2. DualShock 4 Bluetooth 0x11 has the
//!   same layout two bytes later.
//! - b0: low nibble = d-pad hat (0 up, then clockwise in 45 degree steps, 8 = released),
//!   bit 4 square, 5 cross, 6 circle, 7 triangle. b1: bit 0 L1, 1 R1, 2 L2, 3 R2, 4 create /
//!   share, 5 options, 6 L3, 7 R3. b2: bit 0 PS button.

use bevy::input::gamepad::{GamepadAxis, GamepadButton};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// USB vendor id of Sony Interactive Entertainment.
pub const SONY: u16 = 0x054C;

/// Supported product ids and their display names.
const PRODUCTS: &[(u16, &str)] = &[
    (0x0CE6, "DualSense"),
    (0x0DF2, "DualSense Edge"),
    (0x05C4, "DualShock 4"),
    (0x09CC, "DualShock 4"),
];

/// True for the DualSense family (their full report has the triggers before the buttons).
fn is_dualsense(product: u16) -> bool {
    product == 0x0CE6 || product == 0x0DF2
}

/// The buttons a pad reports, in bit order of `HidPad::pressed`.
const BUTTONS: [GamepadButton; 17] = [
    GamepadButton::South,         // cross
    GamepadButton::East,          // circle
    GamepadButton::West,          // square
    GamepadButton::North,         // triangle
    GamepadButton::LeftTrigger,   // L1
    GamepadButton::RightTrigger,  // R1
    GamepadButton::LeftTrigger2,  // L2
    GamepadButton::RightTrigger2, // R2
    GamepadButton::Select,        // create / share
    GamepadButton::Start,         // options
    GamepadButton::LeftThumb,     // L3
    GamepadButton::RightThumb,    // R3
    GamepadButton::Mode,          // PS button
    GamepadButton::DPadUp,
    GamepadButton::DPadDown,
    GamepadButton::DPadLeft,
    GamepadButton::DPadRight,
];

/// The latest input state of one Sony pad.
#[derive(Clone, Debug)]
pub struct HidPad {
    /// Stable id for this connection (1, 2, ... in connection order).
    pub id: u32,
    pub name: String,
    pub product: u16,
    /// Bit i set = BUTTONS[i] held.
    pressed: u32,
    /// Left X, left Y, right X, right Y in -1..1 (Y positive = up, as Bevy reports sticks).
    axes: [f32; 4],
    /// L2, R2 in 0..1.
    triggers: [f32; 2],
}

impl HidPad {
    fn new(id: u32, name: &str, product: u16) -> HidPad {
        HidPad { id, name: name.to_string(), product, pressed: 0, axes: [0.0; 4], triggers: [0.0; 2] }
    }

    /// True while `b` is held.
    pub fn pressed(&self, b: GamepadButton) -> bool {
        BUTTONS.iter().position(|x| *x == b).is_some_and(|i| self.pressed & (1 << i) != 0)
    }

    /// Strength of `b` (0..1): the analog value for L2 / R2, else 0 or 1.
    pub fn value(&self, b: GamepadButton) -> f32 {
        match b {
            GamepadButton::LeftTrigger2 => self.triggers[0].max(self.pressed(b) as u8 as f32),
            GamepadButton::RightTrigger2 => self.triggers[1].max(self.pressed(b) as u8 as f32),
            _ => self.pressed(b) as u8 as f32,
        }
    }

    /// Stick position (-1..1) for `a`; None for axes these pads don't have.
    pub fn axis(&self, a: GamepadAxis) -> Option<f32> {
        match a {
            GamepadAxis::LeftStickX => Some(self.axes[0]),
            GamepadAxis::LeftStickY => Some(self.axes[1]),
            GamepadAxis::RightStickX => Some(self.axes[2]),
            GamepadAxis::RightStickY => Some(self.axes[3]),
            _ => None,
        }
    }

    /// Every button held now.
    pub fn held(&self) -> Vec<GamepadButton> {
        BUTTONS.iter().enumerate().filter(|(i, _)| self.pressed & (1 << i) != 0).map(|(_, b)| *b).collect()
    }

    /// Decode one input report (`data` starts with the report id); unknown reports are ignored.
    fn decode(&mut self, data: &[u8]) {
        let n = data.len();
        if n < 10 {
            return;
        }
        // (offset of LX, DualSense "full" layout?)
        let (o, full) = match (is_dualsense(self.product), data[0]) {
            (true, 0x01) if n >= 64 => (1, true),  // USB
            (true, 0x31) if n >= 13 => (2, true),  // Bluetooth, full report
            (true, 0x01) => (1, false),            // Bluetooth, simple report
            (false, 0x01) => (1, false),           // DualShock 4 USB / Bluetooth simple
            (false, 0x11) if n >= 13 => (3, false), // DualShock 4 Bluetooth, full report
            _ => return,
        };
        let (b0, b1, b2, l2, r2) = if full {
            (data[o + 7], data[o + 8], data[o + 9], data[o + 4], data[o + 5])
        } else {
            if o + 8 >= n {
                return;
            }
            (data[o + 4], data[o + 5], data[o + 6], data[o + 7], data[o + 8])
        };
        let stick = |v: u8| ((v as f32 - 128.0) / 127.0).clamp(-1.0, 1.0);
        self.axes = [stick(data[o]), -stick(data[o + 1]), stick(data[o + 2]), -stick(data[o + 3])];
        self.triggers = [l2 as f32 / 255.0, r2 as f32 / 255.0];
        let hat = b0 & 0x0F;
        let held = [
            b0 & 0x20 != 0,               // cross
            b0 & 0x40 != 0,               // circle
            b0 & 0x10 != 0,               // square
            b0 & 0x80 != 0,               // triangle
            b1 & 0x01 != 0,               // L1
            b1 & 0x02 != 0,               // R1
            b1 & 0x04 != 0,               // L2
            b1 & 0x08 != 0,               // R2
            b1 & 0x10 != 0,               // create / share
            b1 & 0x20 != 0,               // options
            b1 & 0x40 != 0,               // L3
            b1 & 0x80 != 0,               // R3
            b2 & 0x01 != 0,               // PS
            matches!(hat, 7 | 0 | 1),     // up
            matches!(hat, 3 | 4 | 5),     // down
            matches!(hat, 5 | 6 | 7),     // left
            matches!(hat, 1 | 2 | 3),     // right
        ];
        self.pressed = held.iter().enumerate().fold(0, |m, (i, h)| if *h { m | 1 << i } else { m });
    }
}

/// The HID reader: a background thread keeps `pads` up to date.
pub struct Hid {
    pads: Arc<Mutex<Vec<HidPad>>>,
}

impl Hid {
    /// Start the reader thread (it looks for pads once a second and reads them continuously).
    pub fn start() -> Hid {
        let pads = Arc::new(Mutex::new(Vec::new()));
        let shared = pads.clone();
        let _ = std::thread::Builder::new().name("hid-pads".into()).spawn(move || run(shared));
        Hid { pads }
    }

    /// The current state of every connected Sony pad.
    pub fn snapshot(&self) -> Vec<HidPad> {
        self.pads.lock().map(|p| p.clone()).unwrap_or_default()
    }
}

/// Reader thread: open supported pads as they appear, decode their reports, drop them on errors.
fn run(shared: Arc<Mutex<Vec<HidPad>>>) {
    let mut api = match hidapi::HidApi::new() {
        Ok(a) => a,
        Err(e) => {
            psx_runtime::diag::log(format!("hid: cannot initialise ({e}); Sony pads only through the system API"));
            return;
        }
    };
    struct Open {
        dev: hidapi::HidDevice,
        path: std::ffi::CString,
        pad: HidPad,
    }
    let mut open: Vec<Open> = Vec::new();
    let mut next_id = 1u32;
    let mut last_scan: Option<Instant> = None;
    let mut buf = [0u8; 128];
    loop {
        if last_scan.is_none_or(|t| t.elapsed() >= Duration::from_secs(1)) {
            last_scan = Some(Instant::now());
            let _ = api.refresh_devices();
            for info in api.device_list() {
                let Some(&(_, name)) = PRODUCTS.iter().find(|(p, _)| *p == info.product_id()) else { continue };
                // The game controller collection (usage page 1, usage 5 gamepad / 4 joystick).
                if info.vendor_id() != SONY || info.usage_page() != 1 || !matches!(info.usage(), 4 | 5) {
                    continue;
                }
                if open.iter().any(|o| o.path.as_c_str() == info.path()) {
                    continue;
                }
                match info.open_device(&api) {
                    Ok(dev) => {
                        let _ = dev.set_blocking_mode(false);
                        let pad = HidPad::new(next_id, name, info.product_id());
                        psx_runtime::diag::log(format!(
                            "hid pad {next_id} connected: {name} ({:04x}:{:04x}, {:?})",
                            SONY,
                            info.product_id(),
                            info.bus_type()
                        ));
                        next_id += 1;
                        open.push(Open { dev, path: info.path().to_owned(), pad });
                    }
                    Err(e) => psx_runtime::diag::log(format!("hid: cannot open {name}: {e}")),
                }
            }
        }
        open.retain_mut(|o| loop {
            match o.dev.read(&mut buf) {
                Ok(0) => return true,
                Ok(n) => o.pad.decode(&buf[..n]),
                Err(e) => {
                    psx_runtime::diag::log(format!("hid pad {} disconnected ({e})", o.pad.id));
                    return false;
                }
            }
        });
        if let Ok(mut p) = shared.lock() {
            *p = open.iter().map(|o| o.pad.clone()).collect();
        }
        std::thread::sleep(Duration::from_millis(2));
    }
}
