//! Bevy host for the recompiled Tekken 3 (SLUS-00402).
//!
//! The recompiled game runs on its own thread against the emulated PlayStation hardware
//! (psx-runtime). Every vertical blank the GPU's display area is published as an RGBA frame; this
//! app uploads it into a texture on a 4:3 quad in a 3D scene seen by an orthographic camera, plays
//! the SPU's output through the default audio device and feeds keyboard / gamepad input into the
//! emulated controller ports.
//!
//! Keys: F1 debug overlay, F2 controls, F3 whole-VRAM view, F4 write the hardware event journal
//! (t3_events.log), P settings, F11 / Alt+Enter fullscreen.

mod hid;
mod input;
mod settings;

use bevy::asset::RenderAssetUsages;
use bevy::camera::ScalingMode;
use bevy::core_pipeline::tonemapping::Tonemapping;
use bevy::image::ImageSampler;
use bevy::prelude::*;
use bevy::render::render_resource::{Extent3d, TextureDimension, TextureFormat};
use psx_runtime::gpu::{Frame, FrameShared};
use psx_runtime::{audio::AudioShared, diag, CALLS, FN_ENTRIES, LAST_FN, UNKNOWN_TARGETS};
use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;

#[derive(Resource)]
struct Screen {
    frames: Arc<FrameShared>,
    image: Handle<Image>,
    material: Handle<StandardMaterial>,
    seen: u64,
    buf: Frame,
    size: (u32, u32),
    smooth: bool,
    gamma: f32,
    lut: [u8; 256],
}

#[derive(Resource)]
struct PendingLink(Option<(Arc<FrameShared>, Arc<psx_runtime::pad::PadShared>)>);

#[derive(Component)]
struct StatusText;

/// Boot the recompiled game on its own thread, start audio, then run the Bevy window.
fn main() {
    let (mut cpu, shared) = t3_recomp::boot();
    std::thread::Builder::new()
        .name("psx-cpu".into())
        .stack_size(256 << 20)
        .spawn(move || t3_recomp::run(&mut cpu))
        .expect("spawn cpu thread");
    start_audio(shared.audio.clone());

    let mut app = App::new();
    app.insert_resource(ClearColor(Color::BLACK)).add_plugins(DefaultPlugins.set(WindowPlugin {
        primary_window: Some(Window {
            title: "Tekken 3 (Tekken3Decomp)".into(),
            resolution: (1280, 960).into(),
            ..default()
        }),
        ..default()
    }));
    app.insert_resource(PendingLink(Some((shared.frames.clone(), shared.pad.clone()))))
        .insert_resource(input::Input::new(shared.pad.clone()))
        .insert_resource(settings::Settings::load())
        .init_resource::<settings::MenuState>()
        .add_systems(Startup, (setup, input::setup_menu, settings::setup, settings::setup_fps))
        .add_systems(Update, (show_frame, input::read_input, input::menu, settings::menu, fps_counter, update_status, toggle_overlay))
        .run();
}

/// Play the SPU output (44100 Hz stereo) through the default device, resampled to its rate.
fn start_audio(src: Arc<AudioShared>) {
    use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
    let result = (|| -> Result<(), String> {
        let host = cpal::default_host();
        let dev = host.default_output_device().ok_or("no audio output device")?;
        let cfg = dev.default_output_config().map_err(|e| e.to_string())?;
        let channels = cfg.channels() as usize;
        let out_rate = cfg.sample_rate() as f64;
        let config: cpal::StreamConfig = cfg.into();
        let mut pos = 0f64;
        let mut cur = (0i16, 0i16);
        let mut next = (0i16, 0i16);
        let mut buf = Vec::new();
        let stream = dev
            .build_output_stream(
                &config,
                move |data: &mut [f32], _| {
                    let step = src.rate() as f64 / out_rate * src.rate_trim();
                    for frame in data.chunks_mut(channels) {
                        pos += step;
                        while pos >= 1.0 {
                            pos -= 1.0;
                            cur = next;
                            buf.clear();
                            src.pop(1, &mut buf);
                            next = buf[0];
                        }
                        let t = pos as f32;
                        let vol = f32::from_bits(settings::VOLUME.load(Relaxed));
                        let l = (cur.0 as f32 * (1.0 - t) + next.0 as f32 * t) / 32768.0 * vol;
                        let r = (cur.1 as f32 * (1.0 - t) + next.1 as f32 * t) / 32768.0 * vol;
                        for (i, s) in frame.iter_mut().enumerate() {
                            *s = if i % 2 == 0 { l } else { r };
                        }
                    }
                },
                |e| eprintln!("[t3] audio stream error: {e}"),
                None,
            )
            .map_err(|e| e.to_string())?;
        stream.play().map_err(|e| e.to_string())?;
        std::mem::forget(stream); // keep playing for the life of the process
        Ok(())
    })();
    if let Err(e) = result {
        diag::log(format!("audio output unavailable: {e}"));
    }
}

/// The texture the game's picture is uploaded into (sharp or smooth sampling).
fn new_image(w: u32, h: u32, smooth: bool) -> Image {
    let mut img = Image::new_fill(
        Extent3d { width: w, height: h, depth_or_array_layers: 1 },
        TextureDimension::D2,
        &[0, 0, 0, 255],
        TextureFormat::Rgba8UnormSrgb,
        RenderAssetUsages::default(),
    );
    img.sampler = if smooth { ImageSampler::linear() } else { ImageSampler::nearest() };
    img
}

/// Scene: a quad with the picture texture under an orthographic 3D camera, plus the overlays.
fn setup(
    mut commands: Commands,
    mut pending: ResMut<PendingLink>,
    mut images: ResMut<Assets<Image>>,
    mut meshes: ResMut<Assets<Mesh>>,
    mut materials: ResMut<Assets<StandardMaterial>>,
    settings: Res<settings::Settings>,
) {
    let (frames, _pad) = pending.0.take().expect("game link");
    let image = images.add(new_image(320, 240, settings.smooth));
    let material = materials.add(StandardMaterial {
        base_color_texture: Some(image.clone()),
        unlit: true,
        ..default()
    });
    // The console picture: a 4:3 quad facing an orthographic camera that keeps it fitted.
    commands.spawn((
        Camera3d::default(),
        Projection::Orthographic(OrthographicProjection {
            scaling_mode: ScalingMode::AutoMin { min_width: 4.0, min_height: 3.0 },
            ..OrthographicProjection::default_3d()
        }),
        Tonemapping::None,
        Transform::from_xyz(0.0, 0.0, 10.0).looking_at(Vec3::ZERO, Vec3::Y),
    ));
    commands.spawn((
        Mesh3d(meshes.add(Rectangle::new(4.0, 3.0))),
        MeshMaterial3d(material.clone()),
        Transform::IDENTITY,
    ));
    commands.spawn((
        Text::new(""),
        TextFont { font_size: FontSize::Px(14.0), ..default() },
        TextColor(Color::srgb(0.9, 1.0, 0.6)),
        Node { position_type: PositionType::Absolute, top: px(8), left: px(8), ..default() },
        Visibility::Hidden,
        StatusText,
    ));
    commands.insert_resource(Screen {
        frames,
        image,
        material,
        seen: 0,
        buf: Frame::default(),
        size: (320, 240),
        smooth: settings.smooth,
        gamma: f32::NAN,
        lut: [0; 256],
    });
}

/// Upload the newest console frame into the screen texture.
fn show_frame(
    mut screen: ResMut<Screen>,
    mut images: ResMut<Assets<Image>>,
    mut materials: ResMut<Assets<StandardMaterial>>,
    settings: Res<settings::Settings>,
) {
    let s = &mut *screen;
    if s.gamma != settings.gamma {
        s.gamma = settings.gamma;
        for (i, v) in s.lut.iter_mut().enumerate() {
            *v = ((i as f32 / 255.0).powf(1.0 / settings.gamma) * 255.0).round().clamp(0.0, 255.0) as u8;
        }
    }
    let n = s.frames.take_if_new(s.seen, &mut s.buf);
    let restyle = s.smooth != settings.smooth;
    if n == s.seen && !restyle {
        return;
    }
    s.seen = n;
    s.smooth = settings.smooth;
    let (w, h) = (s.buf.width.max(1), s.buf.height.max(1));
    if s.buf.rgba.len() != (w * h * 4) as usize {
        return;
    }
    if s.size != (w, h) || restyle {
        // A new size (or sampler) gets a new texture, and the screen's material is pointed at it:
        // replacing the image asset in place left the material bound to the old texture (black).
        let old = std::mem::replace(&mut s.image, images.add(new_image(w, h, s.smooth)));
        images.remove(&old);
        if let Some(mut mat) = materials.get_mut(&s.material) {
            mat.base_color_texture = Some(s.image.clone());
        }
        s.size = (w, h);
    }
    let Some(mut img) = images.get_mut(&s.image) else { return };
    if let Some(data) = img.data.as_mut() {
        if s.gamma == 1.0 {
            data.copy_from_slice(&s.buf.rgba);
        } else {
            for (d, v) in data.iter_mut().zip(s.buf.rgba.iter()) {
                *d = s.lut[*v as usize];
            }
            for px in data.chunks_exact_mut(4) {
                px[3] = 255;
            }
        }
    }
}

/// Update the FPS counter text (frames shown and the game's own frame rate).
fn fps_counter(
    screen: Option<Res<Screen>>,
    settings: Res<settings::Settings>,
    mut w: Local<settings::FpsWindow>,
    mut q: Query<(&mut Text, &mut Visibility), With<settings::FpsText>>,
) {
    let Some(screen) = screen else { return };
    settings::update_fps(screen.frames.count(), screen.frames.flips(), &settings, &mut w, &mut q);
}

/// Fill the F1 debug overlay: frames, function / call counters, last function, latest log lines.
fn update_status(screen: Option<Res<Screen>>, mut q: Query<(&mut Text, &Visibility), With<StatusText>>) {
    if q.iter().all(|(_, v)| *v == Visibility::Hidden) {
        return;
    }
    let Some(screen) = screen else { return };
    let last = LAST_FN.load(Relaxed);
    let mut s = format!(
        "Tekken 3 recomp - {} functions | frames {} ({}x{})\nfunctions entered {} | indirect calls {} (unresolved {})\n\
         last function {:#010x} {}\nvblanks {} | io r/w {}/{}\n",
        t3_recomp::FUNCTION_COUNT,
        screen.frames.count(),
        screen.size.0,
        screen.size.1,
        FN_ENTRIES.load(Relaxed),
        CALLS.load(Relaxed),
        UNKNOWN_TARGETS.load(Relaxed),
        last,
        t3_recomp::function_name(last).unwrap_or("?"),
        psx_runtime::VBLANKS.load(Relaxed),
        psx_runtime::bus::IO_READS.load(Relaxed),
        psx_runtime::bus::IO_WRITES.load(Relaxed),
    );
    for l in diag::tail(8) {
        s += &format!("> {l}\n");
    }
    for (mut t, _) in &mut q {
        t.0 = s.clone();
    }
}

/// F1 shows / hides the debug overlay; F3 toggles the whole-VRAM view; F4 writes the hardware
/// event journal (t3_events.log) for diagnosing timing and audio problems.
fn toggle_overlay(keys: Res<ButtonInput<KeyCode>>, mut q: Query<&mut Visibility, With<StatusText>>) {
    if keys.just_pressed(KeyCode::F3) {
        // Debug: show the whole video memory instead of the display area.
        let v = &psx_runtime::gpu::SHOW_VRAM;
        v.store(!v.load(Relaxed), Relaxed);
    }
    if keys.just_pressed(KeyCode::F4) {
        // Diagnostics: write the recent hardware events (CD, XA, SPU, DMA) to t3_events.log.
        diag::dump_events();
    }
    if keys.just_pressed(KeyCode::F1) {
        for mut v in &mut q {
            v.toggle_visible_hidden();
        }
    }
}
