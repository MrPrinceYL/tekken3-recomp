//! Controls: keyboard, mouse and gamepads mapped onto the PlayStation digital pads in ports 1
//! and 2.
//!
//! Bindings live in a per-user JSON file (`controls.json` in the platform config folder,
//! e.g. `%APPDATA%\Tekken3Decomp\controls.json`), so everyone who plays a shared copy keeps their
//! own. On first run the file is created from the defaults. F2 opens the in-game rebinding screen.
//!
//! A binding is a list of sources per pad button. Sources are strings:
//! `Key:KeyX`, `Mouse:Left`, `MouseMove:X+`, `Pad:South`, `Axis:LeftStickX+`.
//! Gamepads are read through Bevy (gilrs: XInput / Windows.Gaming.Input), so any common
//! controller works without extra drivers; Sony pads (DualSense, DualShock 4) are read directly
//! over HID instead (hid.rs), since the system API often delivers none of their input over
//! Bluetooth. Port 1 is the keyboard and mouse plus the first gamepad that is used (every gamepad
//! until one is); the second gamepad that is used becomes the pad in port 2, with the same
//! gamepad bindings.
//!
//! Origin calibration: every gamepad axis and analog trigger that rests far from zero right after
//! connecting is re-centred on that rest value (many DirectInput pads expose a trigger as an axis
//! resting at -1, which would otherwise read as a held direction).

use bevy::input::gamepad::{GamepadAxis, GamepadButton};
use bevy::input::mouse::AccumulatedMouseMotion;
use bevy::prelude::*;
use crate::hid;
use psx_runtime::pad::{self, PadShared};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::Arc;

/// Pad buttons in display order.
pub const CONTROLS: &[&str] = &[
    "Cross", "Circle", "Square", "Triangle", "L1", "R1", "L2", "R2", "Start", "Select", "L3", "R3",
    "D-Pad Up", "D-Pad Down", "D-Pad Left", "D-Pad Right",
];

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(default)]
pub struct Controls {
    pub version: u32,
    /// Stick inputs below this are ignored (0..1).
    pub deadzone: f32,
    /// Mouse movement -> virtual stick: tilt per pixel, and how fast it recentres (0..1 per frame).
    pub mouse_sensitivity: f32,
    pub mouse_return: f32,
    pub bindings: BTreeMap<String, Vec<String>>,
}

impl Default for Controls {
    /// Default bindings (see the module docs / README).
    fn default() -> Self {
        let b = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let mut m = BTreeMap::new();
        for (k, v) in [
            ("Cross", b(&["Key:KeyX", "Key:Space", "Pad:South"])),
            ("Circle", b(&["Key:KeyC", "Pad:East"])),
            ("Square", b(&["Key:KeyZ", "Pad:West"])),
            ("Triangle", b(&["Key:KeyV", "Pad:North"])),
            ("L1", b(&["Key:KeyQ", "Pad:LeftTrigger"])),
            ("R1", b(&["Key:KeyE", "Pad:RightTrigger"])),
            ("L2", b(&["Key:Digit1", "Pad:LeftTrigger2"])),
            ("R2", b(&["Key:Digit3", "Pad:RightTrigger2"])),
            ("Start", b(&["Key:Enter", "Pad:Start"])),
            ("Select", b(&["Key:ShiftRight", "Key:Tab", "Pad:Select"])),
            ("L3", b(&["Pad:LeftThumb"])),
            ("R3", b(&["Pad:RightThumb"])),
            ("D-Pad Up", b(&["Key:ArrowUp", "Key:KeyW", "Pad:DPadUp", "Axis:LeftStickY+"])),
            ("D-Pad Down", b(&["Key:ArrowDown", "Key:KeyS", "Pad:DPadDown", "Axis:LeftStickY-"])),
            ("D-Pad Left", b(&["Key:ArrowLeft", "Key:KeyA", "Pad:DPadLeft", "Axis:LeftStickX-"])),
            ("D-Pad Right", b(&["Key:ArrowRight", "Key:KeyD", "Pad:DPadRight", "Axis:LeftStickX+"])),
        ] {
            m.insert(k.to_string(), v);
        }
        Controls { version: 1, deadzone: 0.35, mouse_sensitivity: 0.02, mouse_return: 0.15, bindings: m }
    }
}

/// `controls.json` in the per-user config folder (overridable with `T3_CONTROLS`).
pub fn config_path() -> PathBuf {
    if let Some(p) = std::env::var_os("T3_CONTROLS") {
        return PathBuf::from(p);
    }
    let base = std::env::var_os("APPDATA")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from))
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("Tekken3Decomp").join("controls.json")
}

impl Controls {
    /// Load the user's controls, creating the file with the defaults on first run.
    pub fn load_or_create() -> Controls {
        let path = config_path();
        if let Ok(text) = std::fs::read_to_string(&path) {
            match serde_json::from_str::<Controls>(&text) {
                Ok(mut c) => {
                    // Controls added in later versions get their defaults.
                    for (k, v) in Controls::default().bindings {
                        c.bindings.entry(k).or_insert(v);
                    }
                    return c;
                }
                Err(e) => psx_runtime::diag::log(format!("controls: {} is invalid ({e}); using defaults", path.display())),
            }
        }
        let c = Controls::default();
        c.save();
        c
    }

    /// Write the bindings to controls.json.
    pub fn save(&self) {
        let path = config_path();
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        match serde_json::to_string_pretty(self) {
            Ok(text) => {
                if let Err(e) = std::fs::write(&path, text) {
                    psx_runtime::diag::log(format!("controls: cannot save {}: {e}", path.display()));
                }
            }
            Err(e) => psx_runtime::diag::log(format!("controls: cannot serialize: {e}")),
        }
    }
}

// ---- source names <-> Bevy inputs ----

const KEYS: &[KeyCode] = &[
    KeyCode::KeyA, KeyCode::KeyB, KeyCode::KeyC, KeyCode::KeyD, KeyCode::KeyE, KeyCode::KeyF, KeyCode::KeyG,
    KeyCode::KeyH, KeyCode::KeyI, KeyCode::KeyJ, KeyCode::KeyK, KeyCode::KeyL, KeyCode::KeyM, KeyCode::KeyN,
    KeyCode::KeyO, KeyCode::KeyP, KeyCode::KeyQ, KeyCode::KeyR, KeyCode::KeyS, KeyCode::KeyT, KeyCode::KeyU,
    KeyCode::KeyV, KeyCode::KeyW, KeyCode::KeyX, KeyCode::KeyY, KeyCode::KeyZ, KeyCode::Digit0, KeyCode::Digit1,
    KeyCode::Digit2, KeyCode::Digit3, KeyCode::Digit4, KeyCode::Digit5, KeyCode::Digit6, KeyCode::Digit7,
    KeyCode::Digit8, KeyCode::Digit9, KeyCode::ArrowUp, KeyCode::ArrowDown, KeyCode::ArrowLeft,
    KeyCode::ArrowRight, KeyCode::Space, KeyCode::Enter, KeyCode::Tab, KeyCode::Backquote, KeyCode::ShiftLeft,
    KeyCode::ShiftRight, KeyCode::ControlLeft, KeyCode::ControlRight, KeyCode::AltLeft, KeyCode::AltRight,
    KeyCode::Comma, KeyCode::Period, KeyCode::Slash, KeyCode::Semicolon, KeyCode::Quote, KeyCode::BracketLeft,
    KeyCode::BracketRight, KeyCode::Minus, KeyCode::Equal, KeyCode::Numpad0, KeyCode::Numpad1, KeyCode::Numpad2,
    KeyCode::Numpad3, KeyCode::Numpad4, KeyCode::Numpad5, KeyCode::Numpad6, KeyCode::Numpad7, KeyCode::Numpad8,
    KeyCode::Numpad9, KeyCode::Home, KeyCode::End, KeyCode::PageUp, KeyCode::PageDown, KeyCode::Insert,
    KeyCode::Delete,
];
const PAD_BUTTONS: &[GamepadButton] = &[
    GamepadButton::South, GamepadButton::East, GamepadButton::North, GamepadButton::West, GamepadButton::C,
    GamepadButton::Z, GamepadButton::LeftTrigger, GamepadButton::LeftTrigger2, GamepadButton::RightTrigger,
    GamepadButton::RightTrigger2, GamepadButton::Select, GamepadButton::Start, GamepadButton::Mode,
    GamepadButton::LeftThumb, GamepadButton::RightThumb, GamepadButton::DPadUp, GamepadButton::DPadDown,
    GamepadButton::DPadLeft, GamepadButton::DPadRight,
];
const PAD_AXES: &[GamepadAxis] = &[
    GamepadAxis::LeftStickX, GamepadAxis::LeftStickY, GamepadAxis::RightStickX, GamepadAxis::RightStickY,
    GamepadAxis::LeftZ, GamepadAxis::RightZ,
];
const MOUSE: &[MouseButton] = &[MouseButton::Left, MouseButton::Right, MouseButton::Middle, MouseButton::Back, MouseButton::Forward];

/// Display name of a key or gamepad button.
fn name<T: std::fmt::Debug>(v: &T) -> String {
    format!("{v:?}")
}

#[derive(Clone, Copy)]
enum Source {
    Key(KeyCode),
    Mouse(MouseButton),
    MouseMove(bool, f32), // (x axis?, sign)
    Pad(GamepadButton),
    Axis(GamepadAxis, f32),
}

/// Parse a binding as saved in controls.json.
fn parse(s: &str) -> Option<Source> {
    let (kind, rest) = s.split_once(':')?;
    let signed = |r: &str| -> Option<(String, f32)> {
        let sign = if r.ends_with('+') { 1.0 } else if r.ends_with('-') { -1.0 } else { return None };
        Some((r[..r.len() - 1].to_string(), sign))
    };
    match kind {
        "Key" => KEYS.iter().find(|k| name(*k) == rest).map(|k| Source::Key(*k)),
        "Mouse" => MOUSE.iter().find(|b| name(*b) == rest).map(|b| Source::Mouse(*b)),
        "MouseMove" => signed(rest).map(|(a, s)| Source::MouseMove(a == "X", s)),
        "Pad" => PAD_BUTTONS.iter().find(|b| name(*b) == rest).map(|b| Source::Pad(*b)),
        "Axis" => {
            let (a, s) = signed(rest)?;
            PAD_AXES.iter().find(|x| name(*x) == a).map(|x| Source::Axis(*x, s))
        }
        _ => None,
    }
}

/// One gamepad as the bindings see it: a Bevy (gilrs) gamepad or a Sony pad read over HID.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
enum PadId {
    Bevy(Entity),
    Hid(u32),
}

impl std::fmt::Display for PadId {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            PadId::Bevy(e) => write!(f, "{e}"),
            PadId::Hid(n) => write!(f, "hid{n}"),
        }
    }
}

/// Read access to a gamepad of either kind.
#[derive(Clone, Copy)]
enum PadRef<'a> {
    Bevy(&'a Gamepad),
    Hid(&'a hid::HidPad),
}

impl PadRef<'_> {
    fn pressed(&self, b: GamepadButton) -> bool {
        match self {
            PadRef::Bevy(g) => g.pressed(b),
            PadRef::Hid(h) => h.pressed(b),
        }
    }
    /// Analog value of a button (triggers), if the pad reports one.
    fn button_value(&self, b: GamepadButton) -> Option<f32> {
        match self {
            PadRef::Bevy(g) => g.get(b),
            PadRef::Hid(h) => Some(h.value(b)),
        }
    }
    fn axis(&self, a: GamepadAxis) -> Option<f32> {
        match self {
            PadRef::Bevy(g) => g.get(a),
            PadRef::Hid(h) => h.axis(a),
        }
    }
}

/// Rest-position detection per gamepad input (see the module doc).
#[derive(Default)]
struct Origins {
    /// When each gamepad was first seen.
    connected: HashMap<PadId, std::time::Instant>,
    /// (gamepad, input) -> (candidate value, since when it has been steady)
    candidate: HashMap<(PadId, String), (f32, std::time::Instant)>,
    /// (gamepad, input) -> rest value
    origin: HashMap<(PadId, String), f32>,
}

/// Inputs only count as resting off-centre if they hold still this long right after connecting.
const ORIGIN_WINDOW: std::time::Duration = std::time::Duration::from_millis(2000);
const ORIGIN_STEADY: std::time::Duration = std::time::Duration::from_millis(400);

impl Origins {
    /// Record the resting value of each analog axis / trigger of newly connected gamepads during their
    /// first moments, so bindings measure deflection from rest (calibration).
    fn observe(&mut self, now: std::time::Instant, pads: &[(PadId, PadRef)]) {
        for &(e, g) in pads {
            let since = *self.connected.entry(e).or_insert(now);
            if now.duration_since(since) > ORIGIN_WINDOW {
                continue;
            }
            let inputs = PAD_AXES.iter().map(|a| (name(a), g.axis(*a)))
                .chain([GamepadButton::LeftTrigger2, GamepadButton::RightTrigger2].iter().map(|b| (name(b), g.button_value(*b))));
            for (n, v) in inputs {
                let Some(v) = v else { continue };
                let key = (e, n);
                if self.origin.contains_key(&key) {
                    continue;
                }
                let c = self.candidate.entry(key.clone()).or_insert((v, now));
                if (c.0 - v).abs() > 0.05 {
                    *c = (v, now);
                } else if v.abs() > 0.5 && now.duration_since(c.1) >= ORIGIN_STEADY {
                    psx_runtime::diag::log(format!("gamepad {e}: {} rests at {v:.2}; using it as the origin", key.1));
                    self.origin.insert(key, v);
                }
            }
        }
        self.connected.retain(|e, _| pads.iter().any(|(p, _)| p == e));
    }

    /// Raw value re-centred on the input's origin (unchanged when it rests at zero).
    fn adjust(&self, e: PadId, input: &str, v: f32) -> f32 {
        match self.origin.get(&(e, input.to_string())) {
            Some(&o) => ((v - o) / (1.0 + o.abs())).clamp(-1.0, 1.0),
            None => v,
        }
    }
}

#[derive(Resource)]
pub struct Input {
    pub controls: Controls,
    parsed: Vec<(String, Vec<Source>)>,
    mouse_stick: Vec2,
    origins: Origins,
    pad: Arc<PadShared>,
    /// Sony pads read over HID (see hid.rs).
    hid: hid::Hid,
    /// Buttons each HID pad held last frame (to find newly pressed ones in the F2 menu).
    hid_prev: HashMap<u32, Vec<GamepadButton>>,
    /// Gamepads seen so far (for the connect / disconnect log).
    seen: HashMap<PadId, String>,
    /// When each gamepad first produced input: ports go to gamepads in that order, so a device
    /// that never sends anything (a virtual controller of Steam / DS4Windows, a duplicate entry of
    /// the same pad) cannot take port 1 away from the controller actually in use.
    active: HashMap<PadId, std::time::Instant>,
    // Rebinding screen.
    pub menu_open: bool,
    selected: usize,
    capturing: bool,
}

impl Input {
    /// Input state feeding `pad` (the emulated controller ports); loads controls.json and starts
    /// the HID reader for Sony pads.
    pub fn new(pad: Arc<PadShared>) -> Input {
        let controls = Controls::load_or_create();
        let mut i = Input {
            controls,
            parsed: Vec::new(),
            mouse_stick: Vec2::ZERO,
            origins: Origins::default(),
            pad,
            hid: hid::Hid::start(),
            hid_prev: HashMap::new(),
            seen: HashMap::new(),
            active: HashMap::new(),
            menu_open: false,
            selected: 0,
            capturing: false,
        };
        i.reparse();
        i
    }
    /// Rebuild the binding lookup after the bindings changed.
    fn reparse(&mut self) {
        self.parsed = CONTROLS
            .iter()
            .map(|c| {
                let v = self.controls.bindings.get(*c).map(|l| l.iter().filter_map(|s| parse(s)).collect()).unwrap_or_default();
                (c.to_string(), v)
            })
            .collect();
    }
}

/// Every usable gamepad: Bevy's, except Sony pads that the HID reader already reads (the system
/// API reports them too, usually without input), plus the HID pads.
fn all_pads<'a>(bevy: &'a Query<(Entity, &Gamepad, Option<&Name>)>, hid: &'a [hid::HidPad]) -> Vec<(PadId, PadRef<'a>)> {
    let mut v: Vec<(PadId, PadRef)> = bevy
        .iter()
        .filter(|(_, g, _)| !(g.vendor_id() == Some(hid::SONY) && hid.iter().any(|h| Some(h.product) == g.product_id())))
        .map(|(e, g, _)| (PadId::Bevy(e), PadRef::Bevy(g)))
        .collect();
    v.extend(hid.iter().map(|h| (PadId::Hid(h.id), PadRef::Hid(h))));
    v.sort_by_key(|(id, _)| *id);
    v
}

struct Devices<'a> {
    keys: &'a ButtonInput<KeyCode>,
    mouse: &'a ButtonInput<MouseButton>,
    pads: Vec<(PadId, PadRef<'a>)>,
    origins: &'a Origins,
    mouse_stick: Vec2,
    deadzone: f32,
}

impl Devices<'_> {
    /// 0..1 strength of one source.
    fn value(&self, s: &Source) -> f32 {
        match *s {
            Source::Key(k) => self.keys.pressed(k) as u8 as f32,
            Source::Mouse(b) => self.mouse.pressed(b) as u8 as f32,
            Source::MouseMove(x, sign) => {
                let v = if x { self.mouse_stick.x } else { -self.mouse_stick.y };
                (v * sign).clamp(0.0, 1.0)
            }
            Source::Pad(b) => self
                .pads
                .iter()
                .map(|&(e, g)| self.origins.adjust(e, &name(&b), g.button_value(b).unwrap_or(g.pressed(b) as u8 as f32)))
                .fold(0.0, f32::max),
            Source::Axis(a, sign) => self
                .pads
                .iter()
                .map(|&(e, g)| (self.origins.adjust(e, &name(&a), g.axis(a).unwrap_or(0.0)) * sign).clamp(0.0, 1.0))
                .map(|v| if v < self.deadzone { 0.0 } else { v })
                .fold(0.0, f32::max),
        }
    }
}

const BITS: &[(&str, u16)] = &[
    ("Cross", pad::CROSS), ("Circle", pad::CIRCLE), ("Square", pad::SQUARE), ("Triangle", pad::TRIANGLE),
    ("L1", pad::L1), ("R1", pad::R1), ("L2", pad::L2), ("R2", pad::R2), ("Start", pad::START),
    ("Select", pad::SELECT), ("L3", pad::L3), ("R3", pad::R3), ("D-Pad Up", pad::UP),
    ("D-Pad Down", pad::DOWN), ("D-Pad Left", pad::LEFT), ("D-Pad Right", pad::RIGHT),
];

impl Input {
    /// Pad button bits currently held according to the keyboard and gamepads.
    fn buttons(&self, dev: &Devices) -> u16 {
        let mut b = 0u16;
        for (n, bit) in BITS {
            let v = self.parsed.iter().find(|(c, _)| c == n).map_or(0.0, |(_, l)| l.iter().map(|s| dev.value(s)).fold(0.0, f32::max));
            if v > 0.5 {
                b |= bit;
            }
        }
        // Opposite directions cannot both be held on a real pad.
        if b & (pad::LEFT | pad::RIGHT) == pad::LEFT | pad::RIGHT {
            b &= !(pad::LEFT | pad::RIGHT);
        }
        if b & (pad::UP | pad::DOWN) == pad::UP | pad::DOWN {
            b &= !(pad::UP | pad::DOWN);
        }
        b
    }
}

/// Read every bound source and write the pad states for ports 1 and 2.
pub fn read_input(
    keys: Res<ButtonInput<KeyCode>>,
    mouse: Res<ButtonInput<MouseButton>>,
    motion: Res<AccumulatedMouseMotion>,
    pads: Query<(Entity, &Gamepad, Option<&Name>)>,
    mut input: ResMut<Input>,
) {
    let now = std::time::Instant::now();
    let hid_pads = input.hid.snapshot();
    let all = all_pads(&pads, &hid_pads);
    track_gamepads(&mut input, &pads, &hid_pads);
    input.origins.observe(now, &all);
    let c = input.controls.clone();
    // Mouse movement drives a virtual stick that recentres when the mouse stops.
    let ms = (input.mouse_stick + motion.delta * c.mouse_sensitivity).clamp(Vec2::splat(-1.0), Vec2::splat(1.0));
    input.mouse_stick = ms * (1.0 - c.mouse_return.clamp(0.0, 1.0));
    // Ports by first activity (see `Input::active`); with no active gamepad yet, every gamepad
    // drives port 1 so the first press of any of them works.
    for &(id, g) in &all {
        if !input.active.contains_key(&id) && gamepad_used(&input.origins, id, g) {
            input.active.insert(id, now);
            let port = input.active.len();
            psx_runtime::diag::log(format!("gamepad {id}: first input, it is now the controller for port {}", port.min(2)));
        }
    }
    if input.menu_open || crate::settings::MENU_OPEN.load(std::sync::atomic::Ordering::Relaxed) {
        input.pad.set(0, 0, true);
        input.pad.set(1, 0, input.active.len() >= 2);
        return;
    }
    let mut order: Vec<(PadId, PadRef)> = all.iter().copied().filter(|(id, _)| input.active.contains_key(id)).collect();
    order.sort_by_key(|(id, _)| input.active[id]);
    let pads: Vec<(PadId, PadRef)> = if order.is_empty() { all.clone() } else { order };
    let none = ButtonInput::<KeyCode>::default();
    let none_m = ButtonInput::<MouseButton>::default();
    let two = pads.len() >= 2 && input.active.len() >= 2;
    let p1_pads: Vec<(PadId, PadRef)> = if two { pads[..1].to_vec() } else { pads.clone() };
    let dev1 = Devices { keys: &keys, mouse: &mouse, pads: p1_pads, origins: &input.origins, mouse_stick: ms, deadzone: c.deadzone };
    let b1 = input.buttons(&dev1);
    input.pad.set(0, b1, true);
    if two {
        let dev2 = Devices { keys: &none, mouse: &none_m, pads: pads[1..2].to_vec(), origins: &input.origins, mouse_stick: Vec2::ZERO, deadzone: c.deadzone };
        let b2 = input.buttons(&dev2);
        input.pad.set(1, b2, true);
    } else {
        input.pad.set(1, 0, false);
    }
}

/// Log gamepads appearing / disappearing (name, USB vendor:product) and forget their activity.
fn track_gamepads(input: &mut Input, pads: &Query<(Entity, &Gamepad, Option<&Name>)>, hid_pads: &[hid::HidPad]) {
    let mut now: Vec<(PadId, String)> = pads
        .iter()
        .map(|(e, g, n)| {
            let desc = format!(
                "{} ({:04x}:{:04x})",
                n.map(|n| n.as_str().to_string()).unwrap_or_else(|| "unnamed".into()),
                g.vendor_id().unwrap_or(0),
                g.product_id().unwrap_or(0)
            );
            (PadId::Bevy(e), desc)
        })
        .collect();
    now.extend(hid_pads.iter().map(|h| (PadId::Hid(h.id), format!("{} over HID ({:04x}:{:04x})", h.name, hid::SONY, h.product))));
    for (id, desc) in &now {
        if !input.seen.contains_key(id) {
            psx_runtime::diag::log(format!("gamepad {id} connected: {desc}"));
            input.seen.insert(*id, desc.clone());
        }
    }
    let gone: Vec<PadId> = input.seen.keys().copied().filter(|id| !now.iter().any(|(n, _)| n == id)).collect();
    for id in gone {
        if let Some(d) = input.seen.remove(&id) {
            psx_runtime::diag::log(format!("gamepad {id} disconnected: {d}"));
        }
        input.active.remove(&id);
    }
}

/// True if any button of the gamepad is pressed or any stick / trigger is clearly moved from
/// its resting position.
fn gamepad_used(origins: &Origins, id: PadId, g: PadRef) -> bool {
    PAD_BUTTONS.iter().any(|b| g.pressed(*b))
        || PAD_AXES.iter().any(|a| origins.adjust(id, &name(a), g.axis(*a).unwrap_or(0.0)).abs() > 0.6)
}

// ---- rebinding screen (F2) ----

#[derive(Component)]
pub struct ControlsText;

/// Build the (hidden) F2 controls menu.
pub fn setup_menu(mut commands: Commands) {
    commands.spawn((
        Text::new(""),
        TextFont { font_size: FontSize::Px(15.0), ..default() },
        TextColor(Color::WHITE),
        BackgroundColor(Color::srgba(0.0, 0.0, 0.0, 0.85)),
        Node { position_type: PositionType::Absolute, top: Val::Px(10.0), right: Val::Px(10.0), padding: UiRect::all(Val::Px(10.0)), ..default() },
        Visibility::Hidden,
        ControlsText,
    ));
}

/// F2: open/close. Up/Down select, Enter: add a binding (press the input), Backspace: clear,
/// R: reset all to defaults. Every change is saved to controls.json immediately.
pub fn menu(
    keys: Res<ButtonInput<KeyCode>>,
    mouse: Res<ButtonInput<MouseButton>>,
    pads: Query<(Entity, &Gamepad, Option<&Name>)>,
    mut input: ResMut<Input>,
    mut text: Query<(&mut Text, &mut Visibility), With<ControlsText>>,
) {
    // Newly pressed buttons of the HID pads (Bevy tracks its own gamepads' presses).
    let hid_pads = input.hid.snapshot();
    let mut hid_new: Vec<GamepadButton> = Vec::new();
    for h in &hid_pads {
        let held = h.held();
        let prev = input.hid_prev.get(&h.id).cloned().unwrap_or_default();
        hid_new.extend(held.iter().copied().filter(|b| !prev.contains(b)));
        input.hid_prev.insert(h.id, held);
    }
    if keys.just_pressed(KeyCode::F2) {
        input.menu_open = !input.menu_open;
        input.capturing = false;
    }
    let Ok((mut t, mut vis)) = text.single_mut() else { return };
    *vis = if input.menu_open { Visibility::Visible } else { Visibility::Hidden };
    if !input.menu_open {
        return;
    }
    let sel = input.selected;
    let control = CONTROLS[sel].to_string();
    let mut changed = false;
    if input.capturing {
        // First newly pressed key / mouse button / pad button / pushed axis becomes a binding.
        let mut got: Option<String> = None;
        if let Some(k) = keys.get_just_pressed().find(|k| **k != KeyCode::Enter && **k != KeyCode::F2) {
            if KEYS.contains(k) {
                got = Some(format!("Key:{}", name(k)));
            }
        }
        if got.is_none() {
            got = mouse.get_just_pressed().find(|b| MOUSE.contains(b)).map(|b| format!("Mouse:{}", name(b)));
        }
        if got.is_none() {
            got = hid_new.iter().find(|b| PAD_BUTTONS.contains(b)).map(|b| format!("Pad:{}", name(b)));
        }
        for (id, g) in all_pads(&pads, &hid_pads) {
            if got.is_some() {
                break;
            }
            if let PadRef::Bevy(bg) = g {
                got = bg.get_just_pressed().find(|b| PAD_BUTTONS.contains(b)).map(|b| format!("Pad:{}", name(b)));
            }
            if got.is_none() {
                for a in PAD_AXES {
                    let x = input.origins.adjust(id, &name(a), g.axis(*a).unwrap_or(0.0));
                    if x.abs() > 0.7 {
                        got = Some(format!("Axis:{}{}", name(a), if x > 0.0 { "+" } else { "-" }));
                        break;
                    }
                }
            }
        }
        if keys.just_pressed(KeyCode::Escape) {
            input.capturing = false;
        } else if let Some(g) = got {
            let list = input.controls.bindings.entry(control.clone()).or_default();
            if !list.contains(&g) {
                list.push(g);
            }
            input.capturing = false;
            changed = true;
        }
    } else {
        if keys.just_pressed(KeyCode::ArrowDown) {
            input.selected = (sel + 1) % CONTROLS.len();
        }
        if keys.just_pressed(KeyCode::ArrowUp) {
            input.selected = (sel + CONTROLS.len() - 1) % CONTROLS.len();
        }
        if keys.just_pressed(KeyCode::Enter) {
            input.capturing = true;
        }
        if keys.just_pressed(KeyCode::Backspace) {
            input.controls.bindings.insert(control.clone(), Vec::new());
            changed = true;
        }
        if keys.just_pressed(KeyCode::KeyR) {
            input.controls.bindings = Controls::default().bindings;
            changed = true;
        }
    }
    if changed {
        input.controls.save();
        input.reparse();
    }
    let mut s = format!("CONTROLS  (saved to {})\nUp/Down select | Enter add input | Backspace clear | R reset all | F2 close\n\n", config_path().display());
    for (i, c) in CONTROLS.iter().enumerate() {
        let b = input.controls.bindings.get(*c).map(|l| l.join(", ")).unwrap_or_default();
        let mark = if i == input.selected { if input.capturing { ">> press an input <<  " } else { "> " } } else { "  " };
        s += &format!("{mark}{c:<15} {b}\n");
    }
    t.0 = s;
}
