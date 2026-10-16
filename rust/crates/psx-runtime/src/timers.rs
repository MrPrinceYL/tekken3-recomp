//! Root counters (timers 0-2, I/O 0x1F801100..0x1F80112F).
//!
//! Each counter is kept as (base cycle, value at base); its value at any time is computed from
//! the elapsed source ticks: system clock, dot clock (timer 0), horizontal blanks (timer 1) or
//! system clock / 8 (timer 2). Interrupts (on target and/or on 0xFFFF, one-shot or repeating) are
//! scheduled at the exact cycle the counter gets there and raised by [`update`].

use crate::{Machine, CPU_HZ, CYCLES_PER_LINE, IRQ_TMR0};

#[derive(Default, Clone, Copy)]
pub struct Timer {
    pub mode: u32,
    pub target: u32,
    base_cycle: u64,
    base_value: u64,
    /// Source ticks at the last mode read (for the "reached" flags) / last IRQ check.
    flags_ticks: u64,
    irq_ticks: u64,
    fired: bool,
    stopped: bool,
}

#[derive(Default)]
pub struct Timers {
    pub t: [Timer; 3],
    /// GPU horizontal resolution divider for the dot clock (set by gpu.rs).
    pub dot_div: u32,
}

impl Timers {
    /// Vertical blank hook: nothing to do, counter values are computed from the time (see `value`).
    pub fn vblank(&mut self, _now: u64) {}

    /// Source ticks of timer `n` elapsed since its base, at `now`.
    fn ticks(&self, n: usize, now: u64) -> u64 {
        let t = &self.t[n];
        if t.stopped {
            return 0;
        }
        let dt = now.saturating_sub(t.base_cycle);
        let src = (t.mode >> 8) & 3;
        match (n, src) {
            (0, 1) | (0, 3) => {
                // Dot clock: GPU clock (53.693175 MHz) / horizontal divider.
                let div = self.dot_div.max(4) as u128;
                ((dt as u128 * 53_693_175 / CPU_HZ as u128) / div) as u64
            }
            (1, 1) | (1, 3) => dt / CYCLES_PER_LINE,
            (2, 2) | (2, 3) => dt / 8,
            _ => dt,
        }
    }

    /// Cycles from the base until `ticks` source ticks have elapsed.
    fn cycles_for(&self, n: usize, ticks: u64) -> u64 {
        let t = &self.t[n];
        let src = (t.mode >> 8) & 3;
        match (n, src) {
            (0, 1) | (0, 3) => {
                let div = self.dot_div.max(4) as u128;
                ((ticks as u128 * div * CPU_HZ as u128).div_ceil(53_693_175)) as u64
            }
            (1, 1) | (1, 3) => ticks * CYCLES_PER_LINE,
            (2, 2) | (2, 3) => ticks * 8,
            _ => ticks,
        }
    }

    /// CPU cycles per tick of root counter `n` for its clock source (system, dot clock, hblank, /8).
    fn period(&self, n: usize) -> u64 {
        let t = &self.t[n];
        if t.mode & 8 != 0 && t.target != 0 { t.target as u64 + 1 } else { 0x10000 }
    }

    /// Current value of root counter `n` at time `now`.
    pub fn value(&self, n: usize, now: u64) -> u32 {
        let t = &self.t[n];
        ((t.base_value + self.ticks(n, now)) % self.period(n)) as u32
    }

    /// Number of ticks in (from, to] at which the counter equals `x`.
    fn hits(&self, n: usize, from: u64, to: u64, x: u64) -> u64 {
        let p = self.period(n);
        if x >= p || to <= from {
            return 0;
        }
        let s = self.t[n].base_value;
        let f = |t: u64| -> i128 { ((s + t) as i128 - x as i128).div_euclid(p as i128) };
        (f(to) - f(from)) as u64
    }

    /// The first tick after `after` at which an enabled interrupt condition is met.
    fn next_irq_tick(&self, n: usize, after: u64) -> Option<u64> {
        let t = &self.t[n];
        if t.stopped || (t.fired && t.mode & 0x40 == 0) {
            return None;
        }
        let p = self.period(n);
        let s = t.base_value;
        let next_hit = |x: u64| -> Option<u64> {
            if x >= p {
                return None;
            }
            // Smallest tick > after with (s + tick) % p == x.
            let cur = (s + after) % p;
            let d = if x > cur { x - cur } else { p - cur + x };
            Some(after + d)
        };
        let mut best = None;
        if t.mode & 0x10 != 0 {
            best = next_hit(t.target as u64);
        }
        if t.mode & 0x20 != 0 {
            if let Some(h) = next_hit(0xFFFF) {
                best = Some(best.map_or(h, |b: u64| b.min(h)));
            }
        }
        best
    }

    /// Restart root counter `n` at `value` from time `now`.
    fn rebase(&mut self, n: usize, now: u64, value: u64) {
        let t = &mut self.t[n];
        t.base_cycle = now;
        t.base_value = value;
        t.flags_ticks = 0;
        t.irq_ticks = 0;
    }
}

/// CPU read from the root counter registers (value, mode, target).
pub fn read(m: &mut Machine, p: u32, now: u64) -> u32 {
    let n = ((p - 0x1F80_1100) / 0x10) as usize;
    if n > 2 {
        return 0;
    }
    match p & 0xF {
        0 => m.timers.value(n, now),
        4 => {
            let tk = m.timers.ticks(n, now);
            let from = m.timers.t[n].flags_ticks;
            let tgt = m.timers.t[n].target as u64;
            let reached_t = m.timers.hits(n, from, tk, tgt) > 0;
            let reached_f = m.timers.hits(n, from, tk, 0xFFFF) > 0;
            let t = &mut m.timers.t[n];
            let mut v = t.mode;
            if reached_t {
                v |= 1 << 11;
            }
            if reached_f {
                v |= 1 << 12;
            }
            t.flags_ticks = tk;
            t.mode &= !(3 << 11);
            v
        }
        8 => m.timers.t[n].target,
        _ => 0,
    }
}

/// CPU write to the root counter registers.
pub fn write(m: &mut Machine, p: u32, v: u32, now: u64) {
    let n = ((p - 0x1F80_1100) / 0x10) as usize;
    if n > 2 {
        return;
    }
    match p & 0xF {
        0 => m.timers.rebase(n, now, (v & 0xFFFF) as u64),
        4 => {
            let t = &mut m.timers.t[n];
            t.mode = (v & 0x3FF) | (1 << 10);
            t.fired = false;
            // Timer 2 in sync mode 0 or 3 stops counting.
            t.stopped = n == 2 && v & 1 != 0 && matches!((v >> 1) & 3, 0 | 3);
            m.timers.rebase(n, now, 0);
        }
        8 => {
            // Keep the current value, change the reload/compare point.
            let cur = m.timers.value(n, now) as u64;
            m.timers.t[n].target = v & 0xFFFF;
            m.timers.rebase(n, now, cur);
        }
        _ => {}
    }
}

/// Raise the interrupts of counters that reached their target / 0xFFFF since the last call.
pub fn update(m: &mut Machine, now: u64) {
    for n in 0..3 {
        let tk = m.timers.ticks(n, now);
        let last = m.timers.t[n].irq_ticks;
        if tk <= last {
            continue;
        }
        if let Some(hit) = m.timers.next_irq_tick(n, last) {
            if hit <= tk {
                let t = &mut m.timers.t[n];
                t.fired = true;
                let fire = t.mode & 0x80 == 0 || t.mode & (1 << 10) != 0;
                if t.mode & 0x80 != 0 {
                    t.mode ^= 1 << 10; // toggle mode
                }
                if fire {
                    m.raise(IRQ_TMR0 + n as u32);
                }
                // Skip all but the latest crossing (one interrupt per service, like a level).
                m.timers.t[n].irq_ticks = tk;
                continue;
            }
        }
        m.timers.t[n].irq_ticks = tk;
    }
    let _ = m.timers.cycles_for(0, 0);
}
