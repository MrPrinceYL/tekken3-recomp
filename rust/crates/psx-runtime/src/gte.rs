//! GTE (COP2): the geometry transformation engine.
//!
//! Register file, flags and all 22 commands as documented for the hardware (psx-spx "GTE"):
//! 44-bit MAC overflow checks, IR/colour/SZ/SXY saturation, the UNR division used by perspective
//! projection, the screen XY / Z / colour FIFOs and the MVMVA far-colour quirk.

#[derive(Default)]
pub struct Gte {
    d: [u32; 32],
    c: [u32; 32],
    flag: u32,
}

/// Reciprocal table of the GTE's UNR division (psx-spx "GTE Division Inaccuracy"): 257 entries,
/// built once, so perspective division rounds exactly like the hardware.
fn unr_table() -> &'static [u8; 0x101] {
    static T: std::sync::OnceLock<[u8; 0x101]> = std::sync::OnceLock::new();
    T.get_or_init(|| std::array::from_fn(|i| ((0x40000 / (i as i64 + 0x100) + 1) / 2 - 0x101).max(0) as u8))
}

#[inline]
fn lo(v: u32) -> i32 {
    v as i16 as i32
}
#[inline]
fn hi(v: u32) -> i32 {
    (v >> 16) as i16 as i32
}

impl Gte {
    // ---- register access ----
    pub fn read_data(&mut self, n: u32) -> u32 {
        let n = n as usize & 31;
        match n {
            1 | 3 | 5 | 8 | 9 | 10 | 11 => lo(self.d[n]) as u32,
            7 | 16 | 17 | 18 | 19 => self.d[n] & 0xFFFF,
            15 => self.d[14],
            28 | 29 => {
                let c = |v: i32| ((v >> 7).clamp(0, 0x1F)) as u32;
                c(lo(self.d[9])) | c(lo(self.d[10])) << 5 | c(lo(self.d[11])) << 10
            }
            31 => {
                let v = self.d[30];
                if (v as i32) < 0 { (!v).leading_zeros() } else { v.leading_zeros() }
            }
            _ => self.d[n],
        }
    }

    /// GTE data register write (`mtc2` / `lwc2`). SXYP (15) pushes the screen XY FIFO, IRGB (28)
    /// expands 5:5:5 colour into IR1..IR3; read-only registers ignore writes.
    pub fn write_data(&mut self, n: u32, v: u32) {
        let n = n as usize & 31;
        match n {
            15 => {
                self.d[12] = self.d[13];
                self.d[13] = self.d[14];
                self.d[14] = v;
            }
            28 => {
                self.d[28] = v & 0x7FFF;
                self.d[9] = (v & 0x1F) << 7;
                self.d[10] = ((v >> 5) & 0x1F) << 7;
                self.d[11] = ((v >> 10) & 0x1F) << 7;
            }
            29 | 31 => {}
            _ => self.d[n] = v,
        }
    }

    /// GTE control register read (`cfc2`). Some registers read back sign-extended from 16 bits (a
    /// hardware quirk, including H); FLAG (31) carries the summary error bit 31.
    pub fn read_ctrl(&mut self, n: u32) -> u32 {
        let n = n as usize & 31;
        match n {
            4 | 12 | 20 | 26 | 27 | 29 | 30 => lo(self.c[n]) as u32,
            31 => {
                let f = self.flag & 0x7FFF_F000;
                f | if f & 0x7F87_E000 != 0 { 0x8000_0000 } else { 0 }
            }
            _ => self.c[n],
        }
    }

    /// GTE control register write (`ctc2`): matrices, translation, colours, screen offset, H, depth
    /// cue and Z scale factors. Only the writable bits of FLAG are kept.
    pub fn write_ctrl(&mut self, n: u32, v: u32) {
        let n = n as usize & 31;
        if n == 31 {
            self.flag = v & 0x7FFF_F000;
        } else {
            self.c[n] = v;
        }
    }

    // ---- helpers ----
    fn mat(&self, base: usize, r: usize, col: usize) -> i32 {
        let i = r * 3 + col;
        let w = self.c[base + i / 2];
        if i & 1 == 0 { lo(w) } else { hi(w) }
    }
    /// Vector V0, V1 or V2 (VX, VY, VZ as signed 16-bit), or the IR1..IR3 vector for selector 3.
    fn vec(&self, v: usize) -> [i32; 3] {
        match v {
            0..=2 => [lo(self.d[v * 2]), hi(self.d[v * 2]), lo(self.d[v * 2 + 1])],
            _ => [lo(self.d[9]), lo(self.d[10]), lo(self.d[11])],
        }
    }
    /// IR0..IR3 as a signed 16-bit value.
    fn ir(&self, i: usize) -> i64 {
        lo(self.d[8 + i]) as i64
    }

    /// Record MAC1..MAC3 overflow (44-bit range) in FLAG and wrap the value to 44 bits, as the
    /// hardware accumulator does after every multiply-add.
    fn check_mac(&mut self, i: usize, v: i64) -> i64 {
        if v >= 1 << 43 {
            self.flag |= 1 << (31 - i);
        } else if v < -(1 << 43) {
            self.flag |= 1 << (28 - i);
        }
        // Wrap to 44 bits.
        (v << 20) >> 20
    }
    /// Store MAC1..MAC3 after the overflow check and the `sf` shift (0 or 12); returns the stored value.
    fn set_mac(&mut self, i: usize, v: i64, shift: u32) -> i64 {
        let v = self.check_mac(i, v) >> shift;
        self.d[24 + i] = v as u32;
        v
    }
    /// Saturate into IR1..IR3: 0..0x7FFF with the `lm` bit, else -0x8000..0x7FFF; flags saturation.
    fn set_ir(&mut self, i: usize, v: i64, lm: bool) {
        let min = if lm { 0 } else { -0x8000 };
        let c = v.clamp(min, 0x7FFF);
        if c != v {
            self.flag |= 1 << (24 - i);
        }
        self.d[9 + i] = c as i32 as u32;
    }
    /// Store MAC0 (32-bit result of perspective, depth cue, NCLIP, AVSZ), flagging overflow.
    fn set_mac0(&mut self, v: i64) -> i64 {
        if v > 0x7FFF_FFFF {
            self.flag |= 1 << 16;
        } else if v < -0x8000_0000 {
            self.flag |= 1 << 15;
        }
        self.d[24] = v as i32 as u32;
        v
    }
    /// Push a new depth into the SZ FIFO (SZ0..SZ3), saturated to 0..0xFFFF.
    fn push_sz(&mut self, v: i64) {
        let c = v.clamp(0, 0xFFFF);
        if c != v {
            self.flag |= 1 << 18;
        }
        self.d[16] = self.d[17];
        self.d[17] = self.d[18];
        self.d[18] = self.d[19];
        self.d[19] = c as u32;
    }
    /// Push a projected screen position into the SXY FIFO (SXY0..SXY2), saturated to -0x400..0x3FF.
    fn push_sxy(&mut self, x: i64, y: i64) {
        let cx = x.clamp(-0x400, 0x3FF);
        let cy = y.clamp(-0x400, 0x3FF);
        if cx != x {
            self.flag |= 1 << 14;
        }
        if cy != y {
            self.flag |= 1 << 13;
        }
        self.d[12] = self.d[13];
        self.d[13] = self.d[14];
        self.d[14] = (cx as u32 & 0xFFFF) | ((cy as u32) << 16);
    }
    /// Push MAC1..MAC3 >> 4 as an RGB colour (with the CODE byte of RGBC) into the RGB FIFO.
    fn push_color(&mut self) {
        let mut out = [0u32; 3];
        for (i, o) in out.iter_mut().enumerate() {
            let v = (self.d[25 + i] as i32 as i64) >> 4;
            let c = v.clamp(0, 255);
            if c != v {
                self.flag |= 1 << (21 - i);
            }
            *o = c as u32;
        }
        let code = self.d[6] >> 24;
        self.d[20] = self.d[21];
        self.d[21] = self.d[22];
        self.d[22] = out[0] | out[1] << 8 | out[2] << 16 | code << 24;
    }
    /// The perspective divide H / SZ3 with the hardware's UNR approximation (result 0..0x1FFFF);
    /// flags a divide overflow when H >= SZ3 * 2.
    fn divide(&mut self) -> i64 {
        let h = self.c[26] & 0xFFFF;
        let sz3 = self.d[19] & 0xFFFF;
        if h < sz3 * 2 {
            let z = (sz3 as u16).leading_zeros();
            let n = (h as u64) << z;
            let d = (sz3 as u64) << z;
            let u = unr_table()[((d - 0x7FC0) >> 7) as usize] as u64 + 0x101;
            let d = (0x2000080 - d * u) >> 8;
            let d = (0x0000080 + d * u) >> 8;
            (((n * d) + 0x8000) >> 16).min(0x1FFFF) as i64
        } else {
            self.flag |= 1 << 17;
            0x1FFFF
        }
    }

    /// MAC1..3 = (T << 12 + M * V) >> shift, IR1..3 = saturate.
    fn mat_mul(&mut self, m: usize, v: [i32; 3], t: [i64; 3], shift: u32, lm: bool) {
        for r in 0..3 {
            let mut acc = t[r] << 12;
            for k in 0..3 {
                acc = self.check_mac(r + 1, acc + self.mat(m, r, k) as i64 * v[k] as i64);
            }
            let val = self.set_mac(r + 1, acc, shift);
            self.set_ir(r, val, lm);
        }
    }

    /// RTPS for one vertex: rotate + translate V[v] (RT matrix, TR vector), push SZ / SXY with the
    /// perspective divide; `last` also computes the depth-cue factor IR0 (the last vertex of RTPT).
    fn rtp(&mut self, v: usize, shift: u32, lm: bool, last: bool) {
        let vv = self.vec(v);
        let tr = [self.c[5] as i32 as i64, self.c[6] as i32 as i64, self.c[7] as i32 as i64];
        let mut mac3 = 0;
        for r in 0..3 {
            let mut acc = tr[r] << 12;
            for k in 0..3 {
                acc = self.check_mac(r + 1, acc + self.mat(0, r, k) as i64 * vv[k] as i64);
            }
            let val = self.set_mac(r + 1, acc, shift);
            if r == 2 {
                mac3 = acc;
                // IR3 quirk: the flag is tested on MAC3 >> 12, the value saturates normally.
                let min = if lm { 0 } else { -0x8000 };
                let chk = acc >> 12;
                if chk < -0x8000 || chk > 0x7FFF {
                    self.flag |= 1 << 22;
                }
                self.d[11] = val.clamp(min, 0x7FFF) as i32 as u32;
            } else {
                self.set_ir(r, val, lm);
            }
        }
        self.push_sz(mac3 >> 12);
        let q = self.divide();
        let ofx = self.c[24] as i32 as i64;
        let ofy = self.c[25] as i32 as i64;
        let x = self.set_mac0(q * self.ir(1) + ofx) >> 16;
        let y = self.set_mac0(q * self.ir(2) + ofy) >> 16;
        self.push_sxy(x, y);
        if last {
            let dqa = lo(self.c[27]) as i64;
            let dqb = self.c[28] as i32 as i64;
            let mac0 = self.set_mac0(q * dqa + dqb);
            let ir0 = mac0 >> 12;
            let c = ir0.clamp(0, 0x1000);
            if c != ir0 {
                self.flag |= 1 << 12;
            }
            self.d[8] = c as u32;
        }
    }

    /// The RGBC colour register as three 0..255 channels.
    fn rgb(&self) -> [i64; 3] {
        let c = self.d[6];
        [(c & 0xFF) as i64, ((c >> 8) & 0xFF) as i64, ((c >> 16) & 0xFF) as i64]
    }
    /// Far colour (FC) as a vector.
    fn fc(&self) -> [i64; 3] {
        [self.c[21] as i32 as i64, self.c[22] as i32 as i64, self.c[23] as i32 as i64]
    }
    /// Background colour (BK) as a vector.
    fn bk(&self) -> [i64; 3] {
        [self.c[13] as i32 as i64, self.c[14] as i32 as i64, self.c[15] as i32 as i64]
    }

    /// MAC = MAC + (FC - MAC) * IR0, then >> shift (the depth-cue step).
    fn interpolate(&mut self, mac: [i64; 3], shift: u32, lm: bool) {
        let fc = self.fc();
        let ir0 = self.ir(0);
        let mut tmp = [0i64; 3];
        for i in 0..3 {
            let v = self.set_mac(i + 1, (fc[i] << 12) - mac[i], shift);
            self.set_ir(i, v, false);
            tmp[i] = self.ir(i + 1);
        }
        for i in 0..3 {
            let v = self.set_mac(i + 1, tmp[i] * ir0 + mac[i], shift);
            self.set_ir(i, v, lm);
        }
    }

    /// Lighting for vector V[v]: light matrix times the normal, then the colour matrix plus BK.
    fn light(&mut self, v: usize, shift: u32, lm: bool) {
        let vv = self.vec(v);
        self.mat_mul(8, vv, [0; 3], shift, lm);
        let ir = [self.ir(1) as i32, self.ir(2) as i32, self.ir(3) as i32];
        self.mat_mul(16, ir, self.bk(), shift, lm);
    }

    /// Multiply the lit colour by RGBC (and optionally depth-cue it towards FC), then push the colour FIFO.
    fn color_mul(&mut self, shift: u32, lm: bool, depth: bool) {
        let rgb = self.rgb();
        let mac = [(rgb[0] * self.ir(1)) << 4, (rgb[1] * self.ir(2)) << 4, (rgb[2] * self.ir(3)) << 4];
        if depth {
            self.interpolate(mac, shift, lm);
        } else {
            for i in 0..3 {
                let v = self.set_mac(i + 1, mac[i], shift);
                self.set_ir(i, v, lm);
            }
        }
        self.push_color();
    }

    /// Run one GTE command (`cop2` immediate): the low 6 bits select it, bit 19 is `sf` (shift by 12),
    /// bit 10 is `lm` (clamp IR to positive). Clears FLAG first. This is where a mod would add or
    /// change geometry behaviour.
    pub fn command(&mut self, op: u32) {
        self.flag = 0;
        let shift = if op & (1 << 19) != 0 { 12 } else { 0 };
        let lm = op & (1 << 10) != 0;
        match op & 0x3F {
            0x01 => self.rtp(0, shift, lm, true),
            0x30 => {
                self.rtp(0, shift, lm, false);
                self.rtp(1, shift, lm, false);
                self.rtp(2, shift, lm, true);
            }
            0x06 => {
                let s = |i: usize| (lo(self.d[12 + i]) as i64, hi(self.d[12 + i]) as i64);
                let (s0, s1, s2) = (s(0), s(1), s(2));
                let v = s0.0 * s1.1 + s1.0 * s2.1 + s2.0 * s0.1 - s0.0 * s2.1 - s1.0 * s0.1 - s2.0 * s1.1;
                self.set_mac0(v);
            }
            0x0C => {
                let (d1, d2, d3) = (lo(self.c[0]) as i64, lo(self.c[2]) as i64, lo(self.c[4]) as i64);
                let (i1, i2, i3) = (self.ir(1), self.ir(2), self.ir(3));
                let v = [d2 * i3 - d3 * i2, d3 * i1 - d1 * i3, d1 * i2 - d2 * i1];
                for i in 0..3 {
                    let r = self.set_mac(i + 1, v[i], shift);
                    self.set_ir(i, r, lm);
                }
            }
            0x10 => {
                let rgb = self.rgb();
                self.interpolate([rgb[0] << 16, rgb[1] << 16, rgb[2] << 16], shift, lm);
                self.push_color();
            }
            0x2A => {
                for _ in 0..3 {
                    let c = self.d[20];
                    let rgb = [(c & 0xFF) as i64, ((c >> 8) & 0xFF) as i64, ((c >> 16) & 0xFF) as i64];
                    self.interpolate([rgb[0] << 16, rgb[1] << 16, rgb[2] << 16], shift, lm);
                    self.push_color();
                }
            }
            0x11 => {
                let mac = [self.ir(1) << 12, self.ir(2) << 12, self.ir(3) << 12];
                self.interpolate(mac, shift, lm);
                self.push_color();
            }
            0x12 => {
                let mx = ((op >> 17) & 3) as usize;
                let vsel = ((op >> 15) & 3) as usize;
                let cv = (op >> 13) & 3;
                let v = self.vec(vsel);
                let base = match mx {
                    0 => 0,
                    1 => 8,
                    2 => 16,
                    _ => 0,
                };
                let t = match cv {
                    0 => [self.c[5] as i32 as i64, self.c[6] as i32 as i64, self.c[7] as i32 as i64],
                    1 => self.bk(),
                    2 => self.fc(),
                    _ => [0; 3],
                };
                if mx == 3 {
                    // Garbage matrix: -R<<4, R<<4, IR0 / RT13 / RT13 ...; rare, use RT.
                }
                if cv == 2 {
                    // Far colour bug: the first column only feeds the flags.
                    for r in 0..3 {
                        let first = (t[r] << 12) + self.mat(base, r, 0) as i64 * v[0] as i64;
                        let f = self.check_mac(r + 1, first) >> shift;
                        self.set_ir(r, f, false);
                        let mut acc = self.mat(base, r, 1) as i64 * v[1] as i64;
                        acc = self.check_mac(r + 1, acc + self.mat(base, r, 2) as i64 * v[2] as i64);
                        let val = self.set_mac(r + 1, acc, shift);
                        self.set_ir(r, val, lm);
                    }
                } else {
                    self.mat_mul(base, v, t, shift, lm);
                }
            }
            0x13 => {
                self.light(0, shift, lm);
                self.color_mul(shift, lm, true);
            }
            0x16 => {
                for v in 0..3 {
                    self.light(v, shift, lm);
                    self.color_mul(shift, lm, true);
                }
            }
            0x14 => {
                let ir = [self.ir(1) as i32, self.ir(2) as i32, self.ir(3) as i32];
                self.mat_mul(16, ir, self.bk(), shift, lm);
                self.color_mul(shift, lm, true);
            }
            0x1C => {
                let ir = [self.ir(1) as i32, self.ir(2) as i32, self.ir(3) as i32];
                self.mat_mul(16, ir, self.bk(), shift, lm);
                self.color_mul(shift, lm, false);
            }
            0x1B => {
                self.light(0, shift, lm);
                self.color_mul(shift, lm, false);
            }
            0x3F => {
                for v in 0..3 {
                    self.light(v, shift, lm);
                    self.color_mul(shift, lm, false);
                }
            }
            0x1E => {
                self.light(0, shift, lm);
                self.push_color();
            }
            0x20 => {
                for v in 0..3 {
                    self.light(v, shift, lm);
                    self.push_color();
                }
            }
            0x28 => {
                for i in 0..3 {
                    let x = self.ir(i + 1);
                    let r = self.set_mac(i + 1, x * x, shift);
                    self.set_ir(i, r, lm);
                }
            }
            0x29 => {
                let rgb = self.rgb();
                let mac = [(rgb[0] * self.ir(1)) << 4, (rgb[1] * self.ir(2)) << 4, (rgb[2] * self.ir(3)) << 4];
                self.interpolate(mac, shift, lm);
                self.push_color();
            }
            0x2D => {
                let s = (self.d[17] & 0xFFFF) as i64 + (self.d[18] & 0xFFFF) as i64 + (self.d[19] & 0xFFFF) as i64;
                let v = self.set_mac0(lo(self.c[29]) as i64 * s);
                self.set_otz(v >> 12);
            }
            0x2E => {
                let s = (0..4).map(|i| (self.d[16 + i] & 0xFFFF) as i64).sum::<i64>();
                let v = self.set_mac0(lo(self.c[30]) as i64 * s);
                self.set_otz(v >> 12);
            }
            0x3D => {
                let ir0 = self.ir(0);
                for i in 0..3 {
                    let r = self.set_mac(i + 1, ir0 * self.ir(i + 1), shift);
                    self.set_ir(i, r, lm);
                }
                self.push_color();
            }
            0x3E => {
                let ir0 = self.ir(0);
                for i in 0..3 {
                    let base = (self.d[25 + i] as i32 as i64) << shift;
                    let r = self.set_mac(i + 1, base + ir0 * self.ir(i + 1), shift);
                    self.set_ir(i, r, lm);
                }
                self.push_color();
            }
            _ => {}
        }
    }

    /// Store the average Z (AVSZ3 / AVSZ4) into OTZ, saturated to 0..0xFFFF.
    fn set_otz(&mut self, v: i64) {
        let c = v.clamp(0, 0xFFFF);
        if c != v {
            self.flag |= 1 << 18;
        }
        self.d[7] = c as u32;
    }
}
