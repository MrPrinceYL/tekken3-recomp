//! Audio output path: the SPU's 44100 Hz stereo output, queued here and drained by the host
//! audio stream.
//!
//! The SPU produces samples in step with host time (spu.rs), in bursts of about a millisecond;
//! the host device pulls at its own steady rate. A small jitter buffer absorbs the difference:
//! playback starts once `TARGET_MS` is queued, an underrun outputs silence and re-primes instead
//! of crackling sample by sample, and the consumer nudges its rate (at most ±0.5 %) to keep the
//! queue near the target.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use std::sync::Mutex;

pub const RATE: u32 = 44100;
const TARGET_MS: usize = 50;
const MAX_MS: usize = 400;

pub static UNDERRUNS: AtomicU64 = AtomicU64::new(0);
pub static DROPPED_FRAMES: AtomicU64 = AtomicU64::new(0);
pub static PUSHED: AtomicU64 = AtomicU64::new(0);
pub static SUMSQ: AtomicU64 = AtomicU64::new(0);

pub struct AudioShared {
    samples: Mutex<VecDeque<(i16, i16)>>,
    primed: AtomicBool,
}

impl AudioShared {
    /// Empty output queue.
    pub fn new() -> Self {
        AudioShared { samples: Mutex::new(VecDeque::new()), primed: AtomicBool::new(false) }
    }

    /// Output sample rate (44100 Hz, the SPU's rate).
    pub fn rate(&self) -> u32 {
        RATE
    }

    /// Stereo frames in `ms` milliseconds.
    fn frames(ms: usize) -> usize {
        RATE as usize * ms / 1000
    }

    /// Append SPU output samples for the front end (dropping the oldest if it falls far behind).
    pub fn push(&self, s: &[(i16, i16)]) {
        let mut q = self.samples.lock().unwrap();
        let mut sq = 0u64;
        for &(l, r) in s {
            sq += ((l as i64 * l as i64 + r as i64 * r as i64) >> 8) as u64;
            q.push_back((l, r));
        }
        PUSHED.fetch_add(s.len() as u64, Relaxed);
        SUMSQ.fetch_add(sq, Relaxed);
        let max = Self::frames(MAX_MS);
        if q.len() > max {
            let n = q.len() - max;
            DROPPED_FRAMES.fetch_add(n as u64, Relaxed);
            q.drain(..n);
        }
    }

    /// Stereo frames waiting to be played.
    pub fn queued(&self) -> usize {
        self.samples.lock().unwrap().len()
    }

    /// Resampling correction for the consumer: >1 drains faster when the queue is above the
    /// target, <1 slower when below (bounded to ±0.5 %, inaudible).
    pub fn rate_trim(&self) -> f64 {
        let target = Self::frames(TARGET_MS).max(1) as f64;
        let err = (self.queued() as f64 - target) / target;
        1.0 + (err * 0.005).clamp(-0.005, 0.005)
    }

    /// Pop up to `n` frames; while priming or after an underrun, outputs silence.
    pub fn pop(&self, n: usize, out: &mut Vec<(i16, i16)>) {
        let target = Self::frames(TARGET_MS);
        let mut q = self.samples.lock().unwrap();
        if !self.primed.load(Relaxed) {
            if q.len() < target {
                out.extend(std::iter::repeat_n((0, 0), n));
                return;
            }
            self.primed.store(true, Relaxed);
        }
        for i in 0..n {
            match q.pop_front() {
                Some(s) => out.push(s),
                None => {
                    UNDERRUNS.fetch_add(1, Relaxed);
                    self.primed.store(false, Relaxed);
                    out.extend(std::iter::repeat_n((0, 0), n - i));
                    return;
                }
            }
        }
    }
}

impl Default for AudioShared {
    /// Same as `AudioShared::new`.
    fn default() -> Self {
        Self::new()
    }
}
