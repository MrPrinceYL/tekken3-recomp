//! Player settings and the P menu: volume, window mode, gamma, VSync, picture filtering and the
//! FPS counter.
//!
//! Saved as JSON next to the controls (`%APPDATA%\Tekken3Decomp\settings.json`, or the
//! `T3_SETTINGS` path), so each player keeps their own. Every change applies and saves
//! immediately.
//!
//! The game runs at the console's steady ~59.8 frames per second: its logic is frame-locked to
//! the vertical blank interrupt, as on the PlayStation, and each finished frame is shown at the
//! next retrace. VSync only decides whether the window waits for the monitor.

use bevy::prelude::*;
use bevy::window::{MonitorSelection, PresentMode, PrimaryWindow, VideoModeSelection, WindowMode};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering::Relaxed};

/// Output volume as f32 bits (read by the audio callback).
pub static VOLUME: AtomicU32 = AtomicU32::new(0x3F80_0000); // 1.0
/// The P menu is open (game input is held neutral).
pub static MENU_OPEN: AtomicBool = AtomicBool::new(false);

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Debug)]
pub enum WindowKind {
    Windowed,
    Borderless,
    Fullscreen,
}

#[derive(Serialize, Deserialize, Clone, Resource, Debug)]
#[serde(default)]
pub struct Settings {
    pub version: u32,
    /// 0.0 ..= 1.5
    pub volume: f32,
    pub window: WindowKind,
    /// Display gamma applied to the final image (1.0 = as the console outputs it).
    pub gamma: f32,
    pub vsync: bool,
    /// Bilinear filtering of the console picture (off = sharp pixels).
    pub smooth: bool,
    /// FPS counter in the top-right corner.
    pub show_fps: bool,
    /// CD data reads this many times faster than the console (1 = original, 4, 8); XA music and
    /// movies always keep the original speed. Off by default so the game stays 1:1.
    pub fast_load: u32,
}

impl Default for Settings {
    /// Default settings.
    fn default() -> Self {
        Settings { version: 2, volume: 1.0, window: WindowKind::Windowed, gamma: 1.0, vsync: true, smooth: false, show_fps: true, fast_load: 1 }
    }
}

/// settings.json next to controls.json (or `T3_SETTINGS`).
pub fn settings_path() -> PathBuf {
    if let Some(p) = std::env::var_os("T3_SETTINGS") {
        return PathBuf::from(p);
    }
    crate::input::config_path().with_file_name("settings.json")
}

impl Settings {
    /// Load settings.json, or the defaults.
    pub fn load() -> Settings {
        let s: Settings = std::fs::read_to_string(settings_path())
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default();
        s.sanitized()
    }
    /// Upgrade settings saved by older versions and clamp values into their valid ranges.
    fn sanitized(mut self) -> Settings {
        if self.version < 2 {
            // Version 2: the FPS counter is on by default.
            self.version = 2;
            self.show_fps = true;
        }
        self.volume = self.volume.clamp(0.0, 1.5);
        self.gamma = self.gamma.clamp(0.5, 2.0);
        if !matches!(self.fast_load, 1 | 4 | 8) {
            self.fast_load = 1;
        }
        self
    }
    /// Write settings.json.
    pub fn save(&self) {
        let p = settings_path();
        if let Some(d) = p.parent() {
            let _ = std::fs::create_dir_all(d);
        }
        if let Ok(t) = serde_json::to_string_pretty(self) {
            let _ = std::fs::write(p, t);
        }
    }
    /// Bevy window mode for the fullscreen setting.
    fn window_mode(&self) -> WindowMode {
        match self.window {
            WindowKind::Windowed => WindowMode::Windowed,
            WindowKind::Borderless => WindowMode::BorderlessFullscreen(MonitorSelection::Current),
            WindowKind::Fullscreen => WindowMode::Fullscreen(MonitorSelection::Current, VideoModeSelection::Current),
        }
    }
    /// Bevy present mode for the VSync setting.
    fn present_mode(&self) -> PresentMode {
        if self.vsync { PresentMode::AutoVsync } else { PresentMode::AutoNoVsync }
    }
}

#[derive(Component)]
pub struct SettingsText;

#[derive(Resource, Default)]
pub struct MenuState {
    open: bool,
    selected: usize,
}

const ITEMS: usize = 8;

/// Apply the saved settings to the window at startup and build the (hidden) P settings menu.
pub fn setup(mut commands: Commands, settings: Res<Settings>, mut windows: Query<&mut Window, With<PrimaryWindow>>) {
    commands.spawn((
        Text::new(""),
        TextFont { font_size: FontSize::Px(18.0), ..default() },
        TextColor(Color::WHITE),
        BackgroundColor(Color::srgba(0.0, 0.0, 0.0, 0.85)),
        Node {
            position_type: PositionType::Absolute,
            top: Val::Percent(30.0),
            left: Val::Percent(30.0),
            padding: UiRect::all(Val::Px(16.0)),
            ..default()
        },
        Visibility::Hidden,
        SettingsText,
    ));
    VOLUME.store(settings.volume.to_bits(), Relaxed);
    psx_runtime::cdrom::FAST_LOAD.store(settings.fast_load, Relaxed);
    if let Ok(mut w) = windows.single_mut() {
        w.mode = settings.window_mode();
        w.present_mode = settings.present_mode();
    }
}

/// P: open/close (Esc also closes). Up/Down select, Left/Right change, Enter on "Reset" restores
/// the defaults. F11 / Alt+Enter toggle borderless fullscreen at any time.
pub fn menu(
    keys: Res<ButtonInput<KeyCode>>,
    mut settings: ResMut<Settings>,
    mut state: ResMut<MenuState>,
    mut text: Query<(&mut Text, &mut Visibility), With<SettingsText>>,
    mut windows: Query<&mut Window, With<PrimaryWindow>>,
) {
    let mut changed = false;
    let alt = keys.pressed(KeyCode::AltLeft) || keys.pressed(KeyCode::AltRight);
    if keys.just_pressed(KeyCode::F11) || (alt && keys.just_pressed(KeyCode::Enter)) {
        settings.window = if settings.window == WindowKind::Windowed { WindowKind::Borderless } else { WindowKind::Windowed };
        changed = true;
    }
    if keys.just_pressed(KeyCode::KeyP) || (state.open && keys.just_pressed(KeyCode::Escape)) {
        state.open = !state.open;
    }
    MENU_OPEN.store(state.open, Relaxed);
    if let Ok((mut t, mut vis)) = text.single_mut() {
        *vis = if state.open { Visibility::Visible } else { Visibility::Hidden };
        if state.open {
            if keys.just_pressed(KeyCode::ArrowDown) {
                state.selected = (state.selected + 1) % ITEMS;
            }
            if keys.just_pressed(KeyCode::ArrowUp) {
                state.selected = (state.selected + ITEMS - 1) % ITEMS;
            }
            let dir = keys.just_pressed(KeyCode::ArrowRight) as i32 - keys.just_pressed(KeyCode::ArrowLeft) as i32;
            let enter = keys.just_pressed(KeyCode::Enter) && !alt;
            if dir != 0 || (state.selected == ITEMS - 1 && enter) {
                let s = &mut *settings;
                match state.selected {
                    0 => s.volume = ((s.volume + 0.05 * dir as f32) * 20.0).round() / 20.0,
                    1 => {
                        let order = [WindowKind::Windowed, WindowKind::Borderless, WindowKind::Fullscreen];
                        let i = order.iter().position(|k| *k == s.window).unwrap_or(0) as i32;
                        s.window = order[(i + dir).rem_euclid(3) as usize];
                    }
                    2 => s.gamma = ((s.gamma + 0.05 * dir as f32) * 20.0).round() / 20.0,
                    3 => s.vsync = !s.vsync,
                    4 => s.smooth = !s.smooth,
                    5 => s.show_fps = !s.show_fps,
                    6 => {
                        let order = [1u32, 4, 8];
                        let i = order.iter().position(|f| *f == s.fast_load).unwrap_or(0) as i32;
                        s.fast_load = order[(i + dir).rem_euclid(3) as usize];
                    }
                    _ => *s = Settings::default(),
                }
                *s = s.clone().sanitized();
                changed = true;
            }
            let rows = [
                format!("Volume        < {:>3.0}% >", settings.volume * 100.0),
                format!("Window        < {:?} >", settings.window),
                format!("Gamma         < {:.2} >", settings.gamma),
                format!("VSync         < {} >", if settings.vsync { "On" } else { "Off" }),
                format!("Filtering     < {} >", if settings.smooth { "Smooth" } else { "Sharp pixels" }),
                format!("FPS counter   < {} >", if settings.show_fps { "On" } else { "Off" }),
                format!(
                    "CD loading    < {} >",
                    match settings.fast_load {
                        4 => "Fast (4x)",
                        8 => "Very fast (8x)",
                        _ => "Original",
                    }
                ),
                "Reset to defaults  [Enter]".to_string(),
            ];
            let mut s = String::from("SETTINGS\nUp/Down select | Left/Right change | P / Esc close\n\n");
            for (i, r) in rows.iter().enumerate() {
                s += if i == state.selected { "> " } else { "  " };
                s += r;
                s += "\n";
            }
            t.0 = s;
        }
    }
    if changed {
        settings.save();
        VOLUME.store(settings.volume.to_bits(), Relaxed);
    psx_runtime::cdrom::FAST_LOAD.store(settings.fast_load, Relaxed);
        if let Ok(mut w) = windows.single_mut() {
            let mode = settings.window_mode();
            if w.mode != mode {
                w.mode = mode;
            }
            let pm = settings.present_mode();
            if w.present_mode != pm {
                w.present_mode = pm;
            }
        }
    }
}

#[derive(Component)]
pub struct FpsText;

/// Build the FPS counter text (shown when enabled in the settings).
pub fn setup_fps(mut commands: Commands) {
    commands.spawn((
        Text::new(""),
        TextFont { font_size: FontSize::Px(16.0), ..default() },
        TextColor(Color::srgb(1.0, 1.0, 0.4)),
        BackgroundColor(Color::srgba(0.0, 0.0, 0.0, 0.55)),
        Node {
            position_type: PositionType::Absolute,
            top: Val::Px(8.0),
            right: Val::Px(8.0),
            padding: UiRect::axes(Val::Px(8.0), Val::Px(4.0)),
            ..default()
        },
        Visibility::Hidden,
        FpsText,
    ));
}

/// Window counter for the FPS display: game frames (the console's frames actually produced,
/// i.e. the real game speed; 60 = full speed), averaged over ~0.5 s.
#[derive(Default)]
pub struct FpsWindow {
    start: Option<std::time::Instant>,
    game0: u64,
    flips0: u64,
    text: String,
}

/// `game_frames`: frames sent to the screen (the console's ~60 Hz video rate); `flips`: frames
/// the game itself finished (display-buffer flips), i.e. how fast the game is actually running.
pub fn update_fps(game_frames: u64, flips: u64, settings: &Settings, w: &mut FpsWindow, q: &mut Query<(&mut Text, &mut Visibility), With<FpsText>>) {
    let Ok((mut t, mut vis)) = q.single_mut() else { return };
    *vis = if settings.show_fps { Visibility::Visible } else { Visibility::Hidden };
    let now = std::time::Instant::now();
    let start = *w.start.get_or_insert_with(|| {
        w.game0 = game_frames;
        w.flips0 = flips;
        now
    });
    let dt = now.duration_since(start).as_secs_f64();
    if dt >= 0.5 {
        let video = (game_frames - w.game0) as f64 / dt;
        w.text = format!("{video:.0} FPS");
        w.start = Some(now);
        w.game0 = game_frames;
        w.flips0 = flips;
    }
    if settings.show_fps && t.0 != w.text {
        t.0 = w.text.clone();
    }
}
