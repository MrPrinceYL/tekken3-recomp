//! XA-ADPCM decoding of real-time audio sectors (CD-ROM XA, mode 2 form 2).
//!
//! A sector holds 18 sound groups of 128 bytes; each group carries 8 sound units of 28 4-bit
//! samples (or 4 units of 8-bit samples) with a shift/filter parameter per unit. Units alternate
//! left/right in stereo. Output is resampled from 37800 / 18900 Hz to the SPU's 44100 Hz and goes
//! through the CD volume matrix.

use std::collections::VecDeque;

const K0: [i32; 4] = [0, 60, 115, 98];
const K1: [i32; 4] = [0, 0, -52, -55];

#[derive(Default)]
pub struct XaDecoder {
    old: [[i32; 2]; 2],
    /// Resampler: fractional position and the last two samples per channel.
    frac: f64,
    prev: [i32; 2],
    cur: [i32; 2],
    pub sectors: u64,
}

/// CD volume matrix: vol = [L->L, L->R, R->R, R->L] (0x80 = 100%).
pub fn apply_volume(l: i32, r: i32, vol: [u8; 4]) -> (i16, i16) {
    let lo = (l * vol[0] as i32 + r * vol[3] as i32) >> 7;
    let ro = (r * vol[2] as i32 + l * vol[1] as i32) >> 7;
    (lo.clamp(-32768, 32767) as i16, ro.clamp(-32768, 32767) as i16)
}

impl XaDecoder {
    pub fn reset(&mut self) {
        self.old = [[0; 2]; 2];
        self.frac = 0.0;
        self.prev = [0; 2];
        self.cur = [0; 2];
    }

    pub fn decode_sector(&mut self, sector: &[u8], out: &mut VecDeque<(i16, i16)>, vol: [u8; 4]) {
        self.sectors += 1;
        let coding = sector[19];
        let stereo = coding & 3 == 1;
        let rate = if (coding >> 2) & 3 == 1 { 18900.0 } else { 37800.0 };
        let eight_bit = (coding >> 4) & 3 == 1;
        let mut left = Vec::with_capacity(4032);
        let mut right = Vec::with_capacity(2016);
        for g in 0..18 {
            let grp = &sector[24 + g * 128..24 + (g + 1) * 128];
            let units = if eight_bit { 4 } else { 8 };
            for u in 0..units {
                let param = grp[4 + u];
                let shift = (param & 0xF).min(12) as i32;
                let filter = ((param >> 4) & 3) as usize;
                let ch = if stereo { u & 1 } else { 0 };
                for j in 0..28 {
                    let raw = if eight_bit {
                        ((grp[16 + j * 4 + u] as i8 as i32) << 8) >> shift
                    } else {
                        let b = grp[16 + j * 4 + u / 2];
                        let n = if u & 1 == 0 { b & 0xF } else { b >> 4 };
                        (((n as i32) << 28) >> 16) >> shift
                    };
                    let [o1, o2] = self.old[ch];
                    let s = (raw + ((o1 * K0[filter] + o2 * K1[filter] + 32) >> 6)).clamp(-32768, 32767);
                    self.old[ch] = [s, o1];
                    if ch == 0 {
                        left.push(s);
                    } else {
                        right.push(s);
                    }
                }
            }
        }
        if !stereo {
            right = left.clone();
        }
        // Resample to 44100 Hz (linear).
        let step = rate / 44100.0;
        let n = left.len().min(right.len());
        let mut i = 0usize;
        while i < n {
            while self.frac >= 1.0 && i < n {
                self.frac -= 1.0;
                self.prev = self.cur;
                self.cur = [left[i], right[i]];
                i += 1;
            }
            if self.frac >= 1.0 {
                break;
            }
            let t = self.frac;
            let l = self.prev[0] as f64 + (self.cur[0] - self.prev[0]) as f64 * t;
            let r = self.prev[1] as f64 + (self.cur[1] - self.prev[1]) as f64 * t;
            out.push_back(apply_volume(l as i32, r as i32, vol));
            self.frac += step;
        }
        // Keep the stream bounded if nobody consumes it.
        while out.len() > 44100 {
            out.pop_front();
        }
    }
}
