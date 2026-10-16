//! Software rasterizer for the GPU's drawing commands.
//!
//! Follows the PlayStation GPU's rules: vertex coordinates are 11-bit signed plus the drawing
//! offset; polygons larger than 1023x511 are dropped; quads are drawn as two triangles (v0 v1 v2
//! and v1 v2 v3); pixels on the right/bottom edges are not drawn (top-left fill rule); colours
//! and texture coordinates are interpolated affinely; texture blending is (texel * colour) / 128;
//! 4x4 ordered dithering applies to shaded / blended polygons when enabled; the four
//! semi-transparency modes, texture windows, 4/8/15-bit textures with CLUTs, transparent texel 0,
//! and the mask bit (set / check) behave as on hardware.

use crate::gpu::{Gpu, VRAM_H, VRAM_W};

const DITHER: [[i32; 4]; 4] = [[-4, 0, -3, 1], [2, -2, 3, -1], [-3, 1, -4, 0], [3, -1, 2, -2]];

#[derive(Clone, Copy, Default)]
struct Vtx {
    x: i32,
    y: i32,
    r: i32,
    g: i32,
    b: i32,
    u: i32,
    v: i32,
}

/// Per-primitive drawing parameters.
#[derive(Clone, Copy)]
struct Prim {
    textured: bool,
    raw: bool,
    semi: bool,
    semi_mode: u32,
    dither: bool,
    // Texture page / CLUT.
    tp_x: u32,
    tp_y: u32,
    depth: u32,
    clut_x: u32,
    clut_y: u32,
}

#[inline]
fn sext11(v: u32) -> i32 {
    ((v as i32) << 21) >> 21
}

/// A vertex word (11-bit signed X / Y) plus the drawing offset.
fn vertex(g: &Gpu, w: u32) -> (i32, i32) {
    (sext11(w & 0x7FF) + g.env.off_x, sext11((w >> 16) & 0x7FF) + g.env.off_y)
}

/// A colour word as (r, g, b) 0..255.
fn color(w: u32) -> (i32, i32, i32) {
    ((w & 0xFF) as i32, ((w >> 8) & 0xFF) as i32, ((w >> 16) & 0xFF) as i32)
}

/// Write one VRAM pixel, honouring the mask bit (check / set).
pub fn put_vram(g: &mut Gpu, x: u32, y: u32, v: u16) {
    let i = (y as usize & (VRAM_H - 1)) * VRAM_W + (x as usize & (VRAM_W - 1));
    if g.env.check_mask && g.vram[i] & 0x8000 != 0 {
        return;
    }
    g.vram[i] = v | if g.env.set_mask { 0x8000 } else { 0 };
}

/// GP0(02h): fill a VRAM rectangle with a colour (ignores the drawing area and mask).
pub fn fill(g: &mut Gpu, f: &[u32]) {
    let (r, gg, b) = color(f[0]);
    let c = ((r >> 3) | ((gg >> 3) << 5) | ((b >> 3) << 10)) as u16;
    let x0 = (f[1] & 0x3F0) as usize;
    let y0 = ((f[1] >> 16) & 0x1FF) as usize;
    let w = (((f[2] & 0x3FF) + 0xF) & !0xF) as usize;
    let h = ((f[2] >> 16) & 0x1FF) as usize;
    for y in 0..h {
        let row = ((y0 + y) & (VRAM_H - 1)) * VRAM_W;
        for x in 0..w {
            g.vram[row + ((x0 + x) & (VRAM_W - 1))] = c;
        }
    }
}

/// GP0(80h): copy a VRAM rectangle to another place in VRAM.
pub fn copy(g: &mut Gpu, f: &[u32]) {
    let (sx, sy) = (f[1] & 0x3FF, (f[1] >> 16) & 0x1FF);
    let (dx, dy) = (f[2] & 0x3FF, (f[2] >> 16) & 0x1FF);
    let w = ((f[3] & 0xFFFF).wrapping_sub(1) & 0x3FF) + 1;
    let h = (((f[3] >> 16) & 0xFFFF).wrapping_sub(1) & 0x1FF) + 1;
    let mut line = vec![0u16; w as usize];
    for y in 0..h {
        let srow = ((sy + y) as usize & (VRAM_H - 1)) * VRAM_W;
        for x in 0..w {
            line[x as usize] = g.vram[srow + ((sx + x) as usize & (VRAM_W - 1))];
        }
        for x in 0..w {
            put_vram(g, dx + x, dy + y, line[x as usize]);
        }
    }
}

impl Prim {
    /// Primitive state for one polygon / rectangle: texture page, CLUT, blending, dithering.
    fn new(g: &Gpu, cmd: u32, textured: bool, texpage: u32, clut: u32) -> Prim {
        let tp = if textured { texpage } else { g.env.texpage };
        Prim {
            textured,
            raw: cmd & 1 != 0,
            semi: cmd & 2 != 0,
            semi_mode: (tp >> 5) & 3,
            dither: g.env.texpage & 0x200 != 0,
            tp_x: (tp & 0xF) * 64,
            tp_y: ((tp >> 4) & 1) * 256,
            depth: (tp >> 7) & 3,
            clut_x: (clut & 0x3F) * 16,
            clut_y: (clut >> 6) & 0x1FF,
        }
    }

    /// Texel at (u, v) (after the texture window), or None if transparent (0x0000).
    #[inline]
    fn texel(&self, g: &Gpu, u: i32, v: i32) -> Option<u16> {
        let e = &g.env;
        let u = (u as u32) & 0xFF;
        let v = (v as u32) & 0xFF;
        let u = (u & !(e.tw_mask_x * 8)) | ((e.tw_off_x & e.tw_mask_x) * 8);
        let v = (v & !(e.tw_mask_y * 8)) | ((e.tw_off_y & e.tw_mask_y) * 8);
        let ty = (self.tp_y + v) as usize & (VRAM_H - 1);
        let t = match self.depth {
            0 => {
                let w = g.vram[ty * VRAM_W + ((self.tp_x + u / 4) as usize & (VRAM_W - 1))];
                let idx = (w >> ((u & 3) * 4)) & 0xF;
                g.vram[(self.clut_y as usize & (VRAM_H - 1)) * VRAM_W + ((self.clut_x + idx as u32) as usize & (VRAM_W - 1))]
            }
            1 => {
                let w = g.vram[ty * VRAM_W + ((self.tp_x + u / 2) as usize & (VRAM_W - 1))];
                let idx = (w >> ((u & 1) * 8)) & 0xFF;
                g.vram[(self.clut_y as usize & (VRAM_H - 1)) * VRAM_W + ((self.clut_x + idx as u32) as usize & (VRAM_W - 1))]
            }
            _ => g.vram[ty * VRAM_W + ((self.tp_x + u) as usize & (VRAM_W - 1))],
        };
        (t != 0).then_some(t)
    }
}

/// Shade and write one pixel. `rgb` is the 8-bit vertex colour, `tex` the texel (if textured).
#[inline]
fn plot(g: &mut Gpu, p: &Prim, x: i32, y: i32, rgb: (i32, i32, i32), tex: Option<u16>, dither: bool) {
    let i = (y as usize) * VRAM_W + x as usize;
    let dst = g.vram[i];
    if g.env.check_mask && dst & 0x8000 != 0 {
        return;
    }
    let (mut r, mut gg, mut b, mask_bit, semi);
    match tex {
        Some(t) => {
            let (tr, tg, tb) = ((t & 31) as i32, ((t >> 5) & 31) as i32, ((t >> 10) & 31) as i32);
            if p.raw {
                r = tr << 3;
                gg = tg << 3;
                b = tb << 3;
            } else {
                r = ((tr << 3) * rgb.0) >> 7;
                gg = ((tg << 3) * rgb.1) >> 7;
                b = ((tb << 3) * rgb.2) >> 7;
            }
            mask_bit = t & 0x8000;
            semi = p.semi && t & 0x8000 != 0;
        }
        None => {
            r = rgb.0;
            gg = rgb.1;
            b = rgb.2;
            mask_bit = 0;
            semi = p.semi;
        }
    }
    if dither {
        let d = DITHER[(y & 3) as usize][(x & 3) as usize];
        r += d;
        gg += d;
        b += d;
    }
    let mut r5 = (r.clamp(0, 255) >> 3) as i32;
    let mut g5 = (gg.clamp(0, 255) >> 3) as i32;
    let mut b5 = (b.clamp(0, 255) >> 3) as i32;
    if semi {
        let (br, bg, bb) = ((dst & 31) as i32, ((dst >> 5) & 31) as i32, ((dst >> 10) & 31) as i32);
        let blend = |bk: i32, f: i32| -> i32 {
            match p.semi_mode {
                0 => (bk + f) >> 1,
                1 => bk + f,
                2 => bk - f,
                _ => bk + (f >> 2),
            }
            .clamp(0, 31)
        };
        r5 = blend(br, r5);
        g5 = blend(bg, g5);
        b5 = blend(bb, b5);
    }
    let set = if g.env.set_mask { 0x8000 } else { 0 };
    g.vram[i] = (r5 as u16) | ((g5 as u16) << 5) | ((b5 as u16) << 10) | mask_bit | set;
}

/// True if (x, y) lies inside the drawing area.
fn in_area(g: &Gpu, x: i32, y: i32) -> bool {
    let e = &g.env;
    x >= e.area_x1 && x <= e.area_x2 && y >= e.area_y1 && y <= e.area_y2 && (0..VRAM_W as i32).contains(&x) && (0..VRAM_H as i32).contains(&y)
}

/// GP0 20h-3Fh.
pub fn polygon(g: &mut Gpu, f: &[u32]) {
    let cmd = f[0] >> 24;
    let quad = cmd & 8 != 0;
    let textured = cmd & 4 != 0;
    let gouraud = cmd & 0x10 != 0;
    let n = if quad { 4 } else { 3 };
    let mut v = [Vtx::default(); 4];
    let mut clut = 0;
    let mut texpage = 0;
    // Words: [cmd+c0] [v0] ([t0]) then per further vertex ([cN] if gouraud) [vN] ([tN]).
    let mut i = 1;
    for k in 0..n {
        let col = if k > 0 && gouraud {
            i += 1;
            f[i - 1]
        } else {
            f[0]
        };
        let (x, y) = vertex(g, f[i]);
        i += 1;
        let (r, gg, b) = color(col);
        let (mut uu, mut vv) = (0, 0);
        if textured {
            let t = f[i];
            i += 1;
            uu = (t & 0xFF) as i32;
            vv = ((t >> 8) & 0xFF) as i32;
            if k == 0 {
                clut = t >> 16;
            }
            if k == 1 {
                texpage = t >> 16;
            }
        }
        v[k] = Vtx { x, y, r, g: gg, b, u: uu, v: vv };
    }
    let p = Prim::new(g, cmd, textured, texpage, clut);
    if textured {
        // Textured polygons update the drawing mode's texture page (like GP0 E1h).
        g.env.texpage = (g.env.texpage & !0x9FF) | (texpage & 0x9FF);
    }
    let dither = p.dither && (gouraud || (textured && !p.raw));
    triangle(g, &p, [v[0], v[1], v[2]], gouraud, dither);
    if quad {
        triangle(g, &p, [v[1], v[2], v[3]], gouraud, dither);
    }
}

#[inline]
fn edge(a: (i64, i64), b: (i64, i64), p: (i64, i64)) -> i64 {
    (b.0 - a.0) * (p.1 - a.1) - (b.1 - a.1) * (p.0 - a.0)
}

/// Rasterise one triangle (flat or Gouraud, optionally textured) with the hardware's fill rules.
fn triangle(g: &mut Gpu, p: &Prim, mut t: [Vtx; 3], gouraud: bool, dither: bool) {
    // Size limits.
    let minx = t.iter().map(|v| v.x).min().unwrap();
    let maxx = t.iter().map(|v| v.x).max().unwrap();
    let miny = t.iter().map(|v| v.y).min().unwrap();
    let maxy = t.iter().map(|v| v.y).max().unwrap();
    if maxx - minx >= 1024 || maxy - miny >= 512 {
        return;
    }
    let pt = |v: &Vtx| (v.x as i64, v.y as i64);
    let mut area = edge(pt(&t[0]), pt(&t[1]), pt(&t[2]));
    if area == 0 {
        return;
    }
    if area < 0 {
        t.swap(1, 2);
        area = -area;
    }
    let e = g.env;
    let x0 = minx.max(e.area_x1).max(0);
    let x1 = maxx.min(e.area_x2).min(VRAM_W as i32 - 1);
    let y0 = miny.max(e.area_y1).max(0);
    let y1 = maxy.min(e.area_y2).min(VRAM_H as i32 - 1);
    if x0 > x1 || y0 > y1 {
        return;
    }
    // Top-left rule: an edge is "top" if horizontal and above, "left" if going down
    // (counter-clockwise winding after the swap above, y pointing down).
    let bias = |a: &Vtx, b: &Vtx| -> i64 {
        let top = a.y == b.y && b.x > a.x;
        let left = b.y < a.y;
        if top || left { 0 } else { -1 }
    };
    let b0 = bias(&t[1], &t[2]);
    let b1 = bias(&t[2], &t[0]);
    let b2 = bias(&t[0], &t[1]);
    let flat = (t[0].r, t[0].g, t[0].b);
    for y in y0..=y1 {
        for x in x0..=x1 {
            let pp = (x as i64, y as i64);
            let w0 = edge(pt(&t[1]), pt(&t[2]), pp);
            let w1 = edge(pt(&t[2]), pt(&t[0]), pp);
            let w2 = edge(pt(&t[0]), pt(&t[1]), pp);
            if w0 + b0 < 0 || w1 + b1 < 0 || w2 + b2 < 0 {
                continue;
            }
            let interp = |a: i32, b: i32, c: i32| -> i32 {
                ((w0 * a as i64 + w1 * b as i64 + w2 * c as i64 + area / 2) / area) as i32
            };
            let rgb = if gouraud {
                (interp(t[0].r, t[1].r, t[2].r), interp(t[0].g, t[1].g, t[2].g), interp(t[0].b, t[1].b, t[2].b))
            } else {
                flat
            };
            let tex = if p.textured {
                let u = interp(t[0].u, t[1].u, t[2].u);
                let v = interp(t[0].v, t[1].v, t[2].v);
                match p.texel(g, u, v) {
                    Some(tx) => Some(tx),
                    None => continue,
                }
            } else {
                None
            };
            plot(g, p, x, y, rgb, tex, dither);
        }
    }
}

/// GP0 40h-47h, 50h-57h: one line.
pub fn line(g: &mut Gpu, f: &[u32]) {
    let cmd = f[0] >> 24;
    let gouraud = cmd & 0x10 != 0;
    let (a, b) = if gouraud { ((f[0], f[1]), (f[2], f[3])) } else { ((f[0], f[1]), (f[0], f[2])) };
    draw_line(g, cmd, a, b, gouraud);
}

/// GP0 48h-4Fh, 58h-5Fh: polyline (`words` without the terminator).
pub fn polyline(g: &mut Gpu, words: &[u32]) {
    let cmd = words[0] >> 24;
    let gouraud = cmd & 0x10 != 0;
    let mut pts = Vec::new();
    if gouraud {
        let mut i = 0;
        while i + 1 < words.len() {
            let c = if i == 0 { words[0] } else { words[i] };
            pts.push((c, words[i + 1]));
            i += 2;
        }
    } else {
        for &w in &words[1..] {
            pts.push((words[0], w));
        }
    }
    for s in pts.windows(2) {
        draw_line(g, cmd, s[0], s[1], gouraud);
    }
}

/// Draw one line segment (flat or Gouraud) with the drawing area and mask rules.
fn draw_line(g: &mut Gpu, cmd: u32, a: (u32, u32), b: (u32, u32), gouraud: bool) {
    let p = Prim::new(g, cmd & !4, false, 0, 0);
    let (x0, y0) = vertex(g, a.1);
    let (x1, y1) = vertex(g, b.1);
    if (x1 - x0).abs() >= 1024 || (y1 - y0).abs() >= 512 {
        return;
    }
    let c0 = color(a.0);
    let c1 = if gouraud { color(b.0) } else { c0 };
    let dx = x1 - x0;
    let dy = y1 - y0;
    let steps = dx.abs().max(dy.abs());
    let dither = p.dither && gouraud;
    let rdiv = |n: i32, d: i32| -> i32 { (2 * n + d).div_euclid(2 * d) };
    for s in 0..=steps {
        let (x, y, rgb) = if steps == 0 {
            (x0, y0, c0)
        } else {
            let lerp = |a: i32, b: i32| a + rdiv((b - a) * s, steps);
            (lerp(x0, x1), lerp(y0, y1), (lerp(c0.0, c1.0), lerp(c0.1, c1.1), lerp(c0.2, c1.2)))
        };
        if in_area(g, x, y) {
            plot(g, &p, x, y, rgb, None, dither);
        }
    }
}

/// GP0 60h-7Fh: rectangles and sprites.
pub fn rect(g: &mut Gpu, f: &[u32]) {
    let cmd = f[0] >> 24;
    let textured = cmd & 4 != 0;
    let (x, y) = vertex(g, f[1]);
    let mut i = 2;
    let (mut u0, mut v0, mut clut) = (0, 0, 0);
    if textured {
        u0 = (f[i] & 0xFF) as i32;
        v0 = ((f[i] >> 8) & 0xFF) as i32;
        clut = f[i] >> 16;
        i += 1;
    }
    let (w, h) = match (cmd >> 3) & 3 {
        0 => ((f[i] & 0x3FF) as i32, ((f[i] >> 16) & 0x1FF) as i32),
        1 => (1, 1),
        2 => (8, 8),
        _ => (16, 16),
    };
    // Sprites use the current drawing mode's texture page.
    let p = Prim::new(g, cmd, textured, g.env.texpage, clut);
    let rgb = color(f[0]);
    let flip_x = g.env.texpage & 0x1000 != 0;
    let flip_y = g.env.texpage & 0x2000 != 0;
    let e = g.env;
    for dy in 0..h {
        let py = y + dy;
        if py < e.area_y1 || py > e.area_y2 || py < 0 || py >= VRAM_H as i32 {
            continue;
        }
        for dx in 0..w {
            let px = x + dx;
            if px < e.area_x1 || px > e.area_x2 || px < 0 || px >= VRAM_W as i32 {
                continue;
            }
            let tex = if textured {
                let u = if flip_x { u0 - dx } else { u0 + dx };
                let v = if flip_y { v0 - dy } else { v0 + dy };
                match p.texel(g, u, v) {
                    Some(t) => Some(t),
                    None => continue,
                }
            } else {
                None
            };
            plot(g, &p, px, py, rgb, tex, false);
        }
    }
}
