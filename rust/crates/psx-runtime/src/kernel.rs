//! High-level emulation of the BIOS kernel.
//!
//! The game calls the kernel through the A0h/B0h/C0h function tables (`jr t2` with t1 = function
//! number); `dispatch` sends those addresses here. Implemented: the libc subset the game uses,
//! the heap, events, interrupt chains (SysEnqIntRP), the exception exit hook (HookEntryInt /
//! ReturnFromException), critical sections (syscall 1/2), root counter events and their
//! acknowledge switches (ChangeClearRCnt / ChangeClearPad), the legacy pad services and the
//! memory card services (memcard.rs).
//!
//! Interrupts ([`interrupt`]) follow the BIOS exception handler: save the CPU state, call every
//! queued handler of priorities 0..3 (first function; if it returns nonzero, the second with that
//! value), deliver root counter events, then either return or, if the game installed an exit hook
//! with HookEntryInt, load the registers from its setjmp buffer and continue there with v0 = 1.
//! The hook ends with ReturnFromException, which unwinds back here (no host stack is left behind)
//! and the interrupted state is restored.

use crate::{diag, machine, memcard, Machine};
use psx_core::{Ctx, ATTENTION, GPR_A0, GPR_FP, GPR_GP, GPR_RA, GPR_SP, GPR_T1, GPR_V0, REG_BYTES, REG_CAUSE, SR_IEC, SR_IM2};
use std::collections::VecDeque;
use std::sync::atomic::Ordering::Relaxed;

/// Stack for interrupt handlers called by the kernel (kernel RAM, unused by the game).
const KERNEL_STACK: u32 = 0x8000_EFF0;
/// Fake kernel tables returned by GetB0Table / GetC0Table (some libraries patch them).
const FAKE_B0: u32 = 0x8000_0874;
const FAKE_C0: u32 = 0x8000_0674;
const FAKE_CODE: u32 = 0x8000_2000;

pub const EV_ACTIVE: u32 = 0x2000;
pub const EV_ALREADY: u32 = 0x4000;
pub const EV_WAIT: u32 = 0x1000;

/// Marker unwound by ReturnFromException.
struct ExcReturn;

#[derive(Clone, Copy, Default)]
pub struct Event {
    pub used: bool,
    pub class: u32,
    pub spec: u32,
    pub mode: u32,
    pub func: u32,
    pub status: u32,
}

pub struct Kernel {
    pub events: Vec<Event>,
    /// SysEnqIntRP chain heads (guest addresses of the first element), priorities 0..3.
    chains: [u32; 4],
    /// HookEntryInt buffer (0 = none).
    hook: u32,
    /// ChangeClearRCnt: acknowledge root counter IRQs (0-2 timers, 3 vblank) in the kernel.
    clear_rcnt: [bool; 4],
    clear_pad: bool,
    heap_start: u32,
    heap_end: u32,
    rand_next: u32,
    /// Kernel events to deliver at the next interrupt (class, spec, due cycle).
    pending: VecDeque<(u32, u32, u64)>,
    pad_bufs: [(u32, u32); 2],
    pad_started: bool,
    pad_old: u32,
    pub card: memcard::Cards,
    pub irq_count: u64,
    pub hook_count: u64,
}

impl Kernel {
    /// The kernel's state at boot: no events, no interrupt chains, no exit hook, empty heap.
    pub fn new() -> Self {
        Kernel {
            events: vec![Event::default(); 32],
            chains: [0; 4],
            hook: 0,
            clear_rcnt: [true; 4],
            clear_pad: true,
            heap_start: 0,
            heap_end: 0,
            rand_next: 0x24040001,
            pending: VecDeque::new(),
            pad_bufs: [(0, 0); 2],
            pad_started: false,
            pad_old: 0,
            card: memcard::Cards::open(),
            irq_count: 0,
            hook_count: 0,
        }
    }

    /// A kernel event is due, so an interrupt should be taken even without an I_STAT bit.
    pub fn wants_irq(&self, now: u64) -> bool {
        self.pending.front().is_some_and(|p| p.2 <= now)
    }

    /// Queue an event (class, spec) for delivery at the first interrupt after `delay` cycles.
    pub fn post(&mut self, class: u32, spec: u32, at: u64) {
        self.pending.push_back((class, spec, at));
    }
}

impl Default for Kernel {
    /// Same as `Kernel::new`.
    fn default() -> Self {
        Self::new()
    }
}

// ---- guest memory helpers ----

/// Load a 32-bit word from guest memory.
fn ld32(c: &mut Ctx, a: u32) -> u32 {
    c.ld(a, 4)
}
/// Store a 32-bit word to guest memory.
fn st32(c: &mut Ctx, a: u32, v: u32) {
    c.st(a, 4, v)
}
/// Load a byte from guest memory.
fn ld8(c: &mut Ctx, a: u32) -> u8 {
    c.ld(a, 1) as u8
}
/// Store a byte to guest memory.
fn st8(c: &mut Ctx, a: u32, v: u8) {
    c.st(a, 1, v as u32)
}
/// A NUL-terminated string from guest memory (at most 1024 bytes).
pub fn read_cstr(c: &mut Ctx, mut a: u32) -> String {
    let mut s = Vec::new();
    while s.len() < 1024 {
        let b = ld8(c, a);
        if b == 0 {
            break;
        }
        s.push(b);
        a += 1;
    }
    String::from_utf8_lossy(&s).into_owned()
}
/// Argument register a0..a3 of a BIOS call.
fn arg(c: &Ctx, i: usize) -> u32 {
    c.gpr(GPR_A0 + i)
}
/// Return from a BIOS call with v0 = `v` (the caller's `jal` continues).
fn ret(c: &mut Ctx, v: u32) {
    c.set_gpr(GPR_V0, v);
}

// ---- syscall / break / mtc0 ----

/// `syscall` with a0 = 1 EnterCriticalSection (disable interrupts, returns whether they were
/// enabled), 2 ExitCriticalSection, 0 nothing; other codes are counted in the trace.
pub fn syscall(c: &mut Ctx, _code: u32) {
    let sr = c.sr();
    match arg(c, 0) {
        1 => {
            // EnterCriticalSection
            ret(c, (sr & (SR_IEC | SR_IM2) == (SR_IEC | SR_IM2)) as u32);
            c.set_sr(sr & !(SR_IEC | SR_IM2));
        }
        2 => {
            // ExitCriticalSection
            c.set_sr(sr | SR_IEC | SR_IM2);
            let m = machine();
            if m.irq_pending() || m.kernel.wants_irq(m.now()) {
                ATTENTION.store(true, Relaxed);
            }
        }
        0 => {}
        n => diag::count(&format!("syscall a0={n}")),
    }
}

/// `break`: logged (the game does not use it for control flow).
pub fn brk(_c: &mut Ctx, code: u32) {
    diag::count(&format!("break {code:#x}"));
}

/// Call into an address the recompiled program does not contain.
pub fn fake_call(c: &mut Ctx, addr: u32) -> bool {
    if (FAKE_CODE..FAKE_CODE + 0x1000).contains(&addr) {
        // Entry points inside the fake kernel area (libraries call BIOS internals they patched).
        diag::count(&format!("call into fake kernel code {addr:#010x}"));
        ret(c, 0);
        return true;
    }
    false
}

// ---- interrupts ----

/// Take an interrupt (called from `service` when I_STAT & I_MASK != 0 and the CPU allows it).
pub fn interrupt(c: &mut Ctx) {
    let saved: [u8; REG_BYTES] = c.regs;
    let saved_depth = c.depth;
    let saved_next = std::mem::take(&mut c.next);
    c.in_irq = true;
    let m = machine();
    m.kernel.irq_count += 1;
    let sr = c.sr();
    c.set_sr((sr & !0x3F) | ((sr << 2) & 0x3C));
    c.wr(REG_CAUSE, 4, (c.r(REG_CAUSE, 4) & !0x7C) | 0x400);
    c.set_gpr(GPR_SP, KERNEL_STACK);

    // 1. Interrupt handler chains, priorities 0..3.
    for prio in 0..4 {
        let mut el = machine().kernel.chains[prio];
        let mut guard = 0;
        while el != 0 && guard < 64 {
            let next = ld32(c, el);
            let second = ld32(c, el + 4);
            let first = ld32(c, el + 8);
            if first != 0 {
                let v = c.call_guest(first, &[]);
                if v != 0 && second != 0 {
                    c.call_guest(second, &[v]);
                }
            }
            el = next;
            guard += 1;
        }
    }

    // 2. Kernel services: root counter events, legacy pads, queued events (memory card).
    let m = machine();
    let pend = m.istat & m.imask;
    if pend & 1 != 0 {
        vblank_pads(c);
    }
    let m = machine();
    for (n, bit) in [(0usize, 4u32), (1, 5), (2, 6), (3, 0)] {
        if pend & (1 << bit) != 0 {
            deliver_event(c, 0xF200_0000 | n as u32, 0x0002);
            let m = machine();
            if m.kernel.clear_rcnt[n] {
                m.istat &= !(1 << bit);
            }
        }
    }
    let _ = m;
    let now = machine().now();
    loop {
        let k = &mut machine().kernel;
        let Some(&(class, spec, at)) = k.pending.front() else { break };
        if at > now {
            break;
        }
        k.pending.pop_front();
        deliver_event(c, class, spec);
    }

    // 3. Exit hook installed by the game (libetc's interrupt dispatcher).
    let hook = machine().kernel.hook;
    if hook != 0 {
        machine().kernel.hook_count += 1;
        let ra = ld32(c, hook);
        c.set_gpr(GPR_RA, ra);
        let (sp, fp) = (ld32(c, hook + 4), ld32(c, hook + 8));
        c.set_gpr(GPR_SP, sp);
        c.set_gpr(GPR_FP, fp);
        for i in 0..8 {
            let v = ld32(c, hook + 12 + 4 * i as u32);
            c.set_gpr(16 + i, v);
        }
        let gp = ld32(c, hook + 44);
        c.set_gpr(GPR_GP, gp);
        c.set_gpr(GPR_V0, 1);
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| c.call(ra)));
        match r {
            Ok(()) => diag::count("exception hook returned without ReturnFromException"),
            Err(p) if p.is::<ExcReturn>() => {}
            Err(p) => {
                c.regs = saved;
                c.depth = saved_depth;
                c.next = saved_next;
                c.in_irq = false;
                std::panic::resume_unwind(p);
            }
        }
    }

    c.regs = saved;
    c.depth = saved_depth;
    c.next = saved_next;
    c.in_irq = false;
    // Still pending (not acknowledged)? Try again at the next service.
    if machine().irq_pending() {
        ATTENTION.store(true, Relaxed);
    }
}

/// BIOS pad driver (InitPAD / StartPAD, PAD_init): fill the game's pad buffers at each vertical
/// blank with the digital pad state of both ports.
fn vblank_pads(c: &mut Ctx) {
    let m = machine();
    let k = &mut m.kernel;
    if !k.pad_started {
        return;
    }
    let (b0, c0) = m.shared.pad.get(0);
    let (b1, c1) = m.shared.pad.get(1);
    let bufs = k.pad_bufs;
    let old = k.pad_old;
    for (i, (buf, len)) in bufs.iter().enumerate() {
        if *buf == 0 || *len < 2 {
            continue;
        }
        let (b, conn) = if i == 0 { (b0, c0) } else { (b1, c1) };
        if conn {
            st8(c, *buf, 0x00);
            st8(c, buf + 1, 0x41);
            if *len >= 4 {
                st8(c, buf + 2, !b as u8);
                st8(c, buf + 3, (!b >> 8) as u8);
            }
        } else {
            st8(c, *buf, 0xFF);
        }
    }
    if old != 0 {
        // PAD_init: one word, pad 1 in the low half, pad 2 in the high half, both inverted.
        let swap = |b: u16| ((b & 0xFF) << 8) | (b >> 8);
        let w = (!swap(b0) as u32 & 0xFFFF) | ((if c1 { !swap(b1) } else { 0xFFFF } as u32) << 16);
        st32(c, old, w);
    }
}

/// DeliverEvent: mark matching enabled events as ready / call their handlers.
fn deliver_event(c: &mut Ctx, class: u32, spec: u32) {
    let n = machine().kernel.events.len();
    for i in 0..n {
        let e = machine().kernel.events[i];
        if !e.used || e.class != class || e.spec != spec || e.status != EV_ACTIVE {
            continue;
        }
        if e.mode == 0x2000 {
            machine().kernel.events[i].status = EV_ALREADY;
        } else if e.mode == 0x1000 && e.func != 0 {
            c.call_guest(e.func, &[]);
        }
    }
}

/// Advance kernel timers (memory card operations complete through `post`).
pub fn update(m: &mut Machine, now: u64) {
    if let Some(&(_, _, at)) = m.kernel.pending.front() {
        if at <= now {
            ATTENTION.store(true, Relaxed);
        }
    }
}

// ---- the function tables ----

/// A BIOS function table call: `jr t2` to 0xA0 / 0xB0 / 0xC0 with the function number in t1.
/// Unimplemented functions are counted in the trace and return 0.
pub fn bios_call(c: &mut Ctx, table: u32) {
    let n = c.gpr(GPR_T1);
    let handled = match table {
        0xA0 => a0(c, n),
        0xB0 => b0(c, n),
        _ => c0(c, n),
    };
    if !handled {
        diag::count(&format!("unimplemented BIOS {table:02X}h:{n:02X}h"));
        ret(c, 0);
    }
}

/// Function hooks from sheets/hle.csv.
pub fn hle(c: &mut Ctx, addr: u32, name: &str) -> bool {
    match name {
        "v_wait" => {
            v_wait(c, addr);
            true
        }
        "VSync" if (arg(c, 0) as i32) < 0 => {
            let Some(vc) = vcount_addr(c) else { return false };
            let v = ld32(c, vc);
            let t = std::time::Instant::now();
            while t.elapsed().as_nanos() < 3000 {
                std::hint::spin_loop();
            }
            ret(c, v);
            true
        }
        "StGetNext" => {
            c.call_orig(addr);
            if c.gpr(GPR_V0) != 0 {
                let t = std::time::Instant::now();
                while t.elapsed().as_nanos() < 3000 {
                    std::hint::spin_loop();
                }
            }
            true
        }
        "MDEC_in_sync" => {
            mdec_wait(c, |m| m.mdec.status() & 0x2000_0000 != 0)
        }
        "MDEC_out_sync" => {
            mdec_wait(c, |m| m.dma.ch[1].chcr & 0x0100_0000 != 0)
        }
        "_movie_wait_frame" => movie_wait_frame(c),
        _ => false,
    }
}

/// libpress's MDEC_in_sync / MDEC_out_sync: wait while `busy` holds, servicing interrupts (the
/// MDEC-out slice callbacks run from them), for up to the time the original's 0x100000
/// iterations take on the console (~16 cycles each). Returns false (run the original, which then
/// times out and reports it) only if the limit expires.
fn mdec_wait(c: &mut Ctx, busy: fn(&Machine) -> bool) -> bool {
    let deadline = machine().now() + 0x10_0000 * 16;
    let mut spins = 0u64;
    while busy(machine()) {
        if machine().now() > deadline {
            return false;
        }
        c.poll();
        spins += 1;
        if spins % 256 == 0 {
            std::thread::yield_now();
        }
    }
    ret(c, 0);
    true
}

/// The movie player's `wait_frame(movie)`: spin until the slice callback sets the frame-done flag
/// (+0x34), then clear it. The original gives up after 0x800000 iterations (~5 cycles each on the
/// console, ~1.2 s); here that limit is applied in device time. Returns false (the original runs
/// and takes its timeout path) only if it expires.
fn movie_wait_frame(c: &mut Ctx) -> bool {
    let flag = arg(c, 0).wrapping_add(0x34);
    let deadline = machine().now() + 0x80_0000 * 5;
    let mut spins = 0u64;
    while ld32(c, flag) == 0 {
        if machine().now() > deadline {
            diag::log("movie: frame-done wait expired".into());
            return false;
        }
        c.poll();
        spins += 1;
        if spins % 256 == 0 {
            std::thread::yield_now();
        }
    }
    st32(c, flag, 0);
    true
}

/// libetc's vertical blank counter, from v_wait's `lui/lw` pair (+0x0C/+0x10).
fn vcount_at(c: &mut Ctx, v_wait: u32) -> u32 {
    let (lui, lw) = (ld32(c, v_wait + 0x0C), ld32(c, v_wait + 0x10));
    ((lui & 0xFFFF) << 16).wrapping_add((lw & 0xFFFF) as i16 as i32 as u32)
}

/// Address of libetc's vertical blank counter, read from v_wait's code (see `vcount_at`).
fn vcount_addr(c: &mut Ctx) -> Option<u32> {
    let a = crate::hle_address("v_wait")?;
    Some(vcount_at(c, a))
}

/// libetc's `v_wait(count, timeout)`: spin until the vertical blank counter reaches `count`.
/// The original gives up after `timeout << 15` loop iterations (about 32 cycles each on the
/// console, so ~31 ms per unit); here the same limit is applied in device time. The counter's
/// address is taken from the function's own `lui/lw` pair (+0x0C/+0x10).
fn v_wait(c: &mut Ctx, addr: u32) {
    let vcount = vcount_at(c, addr);
    let target = arg(c, 0) as i32;
    let iters = (arg(c, 1) as u64) << 15;
    let deadline = machine().now() + iters * 32;
    let mut spins = 0u64;
    loop {
        if target <= ld32(c, vcount) as i32 {
            return;
        }
        if machine().now() > deadline {
            diag::log("puts: VSync: timeout".into());
            machine().kernel.clear_pad = false;
            machine().kernel.clear_rcnt[3] = false;
            return;
        }
        c.poll();
        spins += 1;
        if spins % 256 == 0 {
            std::thread::yield_now();
        }
    }
}

/// BIOS table A0h: C library (memcpy, strcmp, rand, malloc ...), heap, FlushCache, GPU helpers,
/// CD / card helpers.
fn a0(c: &mut Ctx, n: u32) -> bool {
    match n {
        0x0E => {
            let v = arg(c, 0) as i32;
            ret(c, v.wrapping_abs() as u32);
        }
        0x13 => {
            // setjmp (SaveState)
            let b = arg(c, 0);
            let vals = [c.gpr(GPR_RA), c.gpr(GPR_SP), c.gpr(GPR_FP)];
            for (i, v) in vals.iter().enumerate() {
                st32(c, b + 4 * i as u32, *v);
            }
            for i in 0..8 {
                let v = c.gpr(16 + i);
                st32(c, b + 12 + 4 * i as u32, v);
            }
            let gp = c.gpr(GPR_GP);
            st32(c, b + 44, gp);
            ret(c, 0);
        }
        0x15 | 0x16 => {
            // strcat / strncat
            let (d, s) = (arg(c, 0), arg(c, 1));
            let lim = if n == 0x16 { arg(c, 2) } else { u32::MAX };
            let mut e = d;
            while ld8(c, e) != 0 {
                e += 1;
            }
            let mut i = 0;
            while i < lim {
                let b = ld8(c, s + i);
                if b == 0 {
                    break;
                }
                st8(c, e + i, b);
                i += 1;
            }
            st8(c, e + i, 0);
            ret(c, d);
        }
        0x17 | 0x18 => {
            let (a, b) = (arg(c, 0), arg(c, 1));
            let lim = if n == 0x18 { arg(c, 2) } else { u32::MAX };
            let mut r = 0i32;
            let mut i = 0;
            while i < lim {
                let (x, y) = (ld8(c, a + i), ld8(c, b + i));
                if x != y {
                    r = x as i32 - y as i32;
                    break;
                }
                if x == 0 {
                    break;
                }
                i += 1;
            }
            ret(c, r as u32);
        }
        0x19 | 0x1A => {
            let (d, s) = (arg(c, 0), arg(c, 1));
            if n == 0x19 {
                let mut i = 0;
                loop {
                    let b = ld8(c, s + i);
                    st8(c, d + i, b);
                    if b == 0 {
                        break;
                    }
                    i += 1;
                }
            } else {
                let lim = arg(c, 2);
                let mut ended = false;
                for i in 0..lim {
                    let b = if ended { 0 } else { ld8(c, s + i) };
                    if b == 0 {
                        ended = true;
                    }
                    st8(c, d + i, b);
                }
            }
            ret(c, d);
        }
        0x1B => {
            let s = arg(c, 0);
            let mut i = 0;
            while ld8(c, s + i) != 0 {
                i += 1;
            }
            ret(c, i);
        }
        0x24 => {
            // strstr
            let (h, nd) = (read_cstr(c, arg(c, 0)), read_cstr(c, arg(c, 1)));
            let r = h.find(&nd).map(|i| arg(c, 0) + i as u32).unwrap_or(0);
            ret(c, r);
        }
        0x25 => {
            let ch = arg(c, 0) as u8;
            ret(c, ch.to_ascii_uppercase() as u32);
        }
        0x26 => {
            let ch = arg(c, 0) as u8;
            ret(c, ch.to_ascii_lowercase() as u32);
        }
        0x28 => {
            // bzero
            let (d, len) = (arg(c, 0), arg(c, 1));
            for i in 0..len {
                st8(c, d + i, 0);
            }
            ret(c, d);
        }
        0x2A => {
            let (d, s, len) = (arg(c, 0), arg(c, 1), arg(c, 2));
            for i in 0..len {
                let b = ld8(c, s + i);
                st8(c, d + i, b);
            }
            ret(c, d);
        }
        0x2B => {
            let (d, v, len) = (arg(c, 0), arg(c, 1) as u8, arg(c, 2));
            for i in 0..len {
                st8(c, d + i, v);
            }
            ret(c, d);
        }
        0x2E => {
            let (s, v, len) = (arg(c, 0), arg(c, 1) as u8, arg(c, 2));
            let mut r = 0;
            for i in 0..len {
                if ld8(c, s + i) == v {
                    r = s + i;
                    break;
                }
            }
            ret(c, r);
        }
        0x2F => {
            let k = &mut machine().kernel;
            k.rand_next = k.rand_next.wrapping_mul(0x41C6_4E6D).wrapping_add(0x3039);
            let v = (k.rand_next >> 16) & 0x7FFF;
            ret(c, v);
        }
        0x30 => machine().kernel.rand_next = arg(c, 0),
        0x33 => {
            let v = malloc(c, arg(c, 0));
            ret(c, v);
        }
        0x34 => free(c, arg(c, 0)),
        0x39 => {
            let (a, size) = (arg(c, 0), arg(c, 1));
            init_heap(c, a, size);
        }
        0x3A | 0x06 => {
            diag::log(format!("game called exit({})", arg(c, 0) as i32));
        }
        0x3E => {
            let s = read_cstr(c, arg(c, 0));
            diag::log(format!("puts: {s}"));
        }
        0x3F => {
            let s = printf(c);
            diag::log(format!("printf: {}", s.trim_end()));
            ret(c, s.len() as u32);
        }
        0x44 => {}       // FlushCache
        0x72 | 0x56 => {} // _96_remove: the BIOS CD handlers are not installed anyway
        0x9F => {}       // SetMem
        0x49 => {
            // GPU_cw: send a GP0 command word.
            crate::gpu::write_gp0(machine(), arg(c, 0));
            ret(c, 1);
        }
        0x70 | 0x55 => memcard::bu_init(c),
        0xAB => memcard::card_info(c, arg(c, 0)),
        0xAC => memcard::card_load(c, arg(c, 0)),
        _ => return false,
    }
    true
}

/// BIOS table B0h: events, pad driver, file I/O on the memory card, exception hook control.
fn b0(c: &mut Ctx, n: u32) -> bool {
    match n {
        0x07 => {
            let (class, spec) = (arg(c, 0), arg(c, 1));
            deliver_event(c, class, spec);
            ret(c, 1);
        }
        0x08 => {
            let (class, spec, mode, func) = (arg(c, 0), arg(c, 1), arg(c, 2), arg(c, 3));
            let k = &mut machine().kernel;
            let r = match k.events.iter().position(|e| !e.used) {
                Some(i) => {
                    k.events[i] = Event { used: true, class, spec, mode, func, status: EV_WAIT };
                    0xF100_0000 | i as u32
                }
                None => 0xFFFF_FFFF,
            };
            ret(c, r);
        }
        0x09 | 0x0A | 0x0B | 0x0C | 0x0D => {
            let i = (arg(c, 0) & 0xFFFF) as usize;
            let mut r = 0;
            if i < machine().kernel.events.len() {
                match n {
                    0x09 => {
                        machine().kernel.events[i].used = false;
                        r = 1;
                    }
                    0x0A => {
                        // WaitEvent: run interrupts until the event is ready.
                        let mut spins = 0u64;
                        loop {
                            let e = machine().kernel.events[i];
                            if !e.used || e.status != EV_ACTIVE && e.status != EV_ALREADY {
                                r = 0;
                                break;
                            }
                            if e.status == EV_ALREADY {
                                machine().kernel.events[i].status = EV_ACTIVE;
                                r = 1;
                                break;
                            }
                            c.poll();
                            spins += 1;
                            if spins % 4096 == 0 {
                                std::thread::yield_now();
                            }
                        }
                    }
                    0x0B => {
                        let e = &mut machine().kernel.events[i];
                        if e.status == EV_ALREADY {
                            e.status = EV_ACTIVE;
                            r = 1;
                        }
                    }
                    0x0C => {
                        machine().kernel.events[i].status = EV_ACTIVE;
                        r = 1;
                    }
                    _ => {
                        machine().kernel.events[i].status = EV_WAIT;
                        r = 1;
                    }
                }
            }
            ret(c, r);
        }
        0x20 => {
            // UnDeliverEvent
            let (class, spec) = (arg(c, 0), arg(c, 1));
            for e in machine().kernel.events.iter_mut() {
                if e.used && e.class == class && e.spec == spec && e.status == EV_ALREADY && e.mode == 0x2000 {
                    e.status = EV_ACTIVE;
                }
            }
        }
        0x12 => {
            // InitPAD(buf1, siz1, buf2, siz2)
            let k = &mut machine().kernel;
            k.pad_bufs = [(arg(c, 0), arg(c, 1)), (arg(c, 2), arg(c, 3))];
            ret(c, 2);
        }
        0x13 => {
            machine().kernel.pad_started = true;
            let sr = c.sr();
            c.set_sr(sr | SR_IEC | SR_IM2);
            ret(c, 1);
        }
        0x14 => machine().kernel.pad_started = false,
        0x15 => {
            // PAD_init(type, buf)
            let k = &mut machine().kernel;
            k.pad_old = arg(c, 1);
            k.pad_started = true;
            ret(c, 2);
        }
        0x16 => {
            // PAD_dr: current buttons (inverted, pad 1 low / pad 2 high).
            let m = machine();
            let (b0v, _) = m.shared.pad.get(0);
            let (b1v, c1) = m.shared.pad.get(1);
            let swap = |b: u16| ((b & 0xFF) << 8) | (b >> 8);
            let w = (!swap(b0v) as u32 & 0xFFFF) | ((if c1 { !swap(b1v) } else { 0xFFFF } as u32) << 16);
            let buf = m.kernel.pad_old;
            if buf != 0 {
                st32(c, buf, w);
            }
            ret(c, w);
        }
        0x17 => {
            // ReturnFromException
            if c.in_irq {
                std::panic::resume_unwind(Box::new(ExcReturn));
            }
            diag::count("ReturnFromException outside an interrupt");
        }
        0x18 => machine().kernel.hook = 0, // ResetEntryInt (SetDefaultExitFromException)
        0x19 => machine().kernel.hook = arg(c, 0),
        0x32..=0x37 | 0x41..=0x45 => memcard::file_call(c, n),
        0x38 => diag::log(format!("game called exit({})", arg(c, 0) as i32)),
        0x3D => {}
        0x3F => {
            let s = read_cstr(c, arg(c, 0));
            diag::log(format!("puts: {s}"));
        }
        0x4A => memcard::init_card(c),
        0x4B => memcard::start_card(c),
        0x4C => {}
        0x4E => memcard::card_write(c),
        0x4F => memcard::card_read(c),
        0x50 => memcard::new_card(c),
        0x56 => ret(c, FAKE_C0),
        0x57 => ret(c, FAKE_B0),
        0x5B => machine().kernel.clear_pad = arg(c, 0) != 0,
        0x5C => ret(c, 0x11), // _card_status: ready
        _ => return false,
    }
    true
}

/// BIOS table C0h: interrupt handler chains (SysEnqIntRP / SysDeqIntRP), root counter interrupt clearing.
fn c0(c: &mut Ctx, n: u32) -> bool {
    match n {
        0x02 => {
            // SysEnqIntRP(prio, struct): push at the head of the chain.
            let (p, s) = ((arg(c, 0) & 3) as usize, arg(c, 1));
            let head = machine().kernel.chains[p];
            st32(c, s, head);
            machine().kernel.chains[p] = s;
            ret(c, 0);
        }
        0x03 => {
            // SysDeqIntRP(prio, struct)
            let (p, s) = ((arg(c, 0) & 3) as usize, arg(c, 1));
            let mut prev = 0u32;
            let mut el = machine().kernel.chains[p];
            while el != 0 {
                let next = ld32(c, el);
                if el == s {
                    if prev == 0 {
                        machine().kernel.chains[p] = next;
                    } else {
                        st32(c, prev, next);
                    }
                    break;
                }
                prev = el;
                el = next;
            }
            ret(c, 0);
        }
        0x0A => {
            // ChangeClearRCnt(t, flag): returns the old flag.
            let (t, f) = ((arg(c, 0) & 3) as usize, arg(c, 1) != 0);
            let k = &mut machine().kernel;
            let old = k.clear_rcnt[t];
            k.clear_rcnt[t] = f;
            ret(c, old as u32);
        }
        _ => return false,
    }
    true
}

/// Fill the fake kernel tables so code that patches BIOS internals writes harmless RAM.
pub fn install_fake_tables(c: &mut Ctx) {
    for i in 0..0x60u32 {
        st32(c, FAKE_B0 + 4 * i, FAKE_CODE + 0x10 * i);
    }
    for i in 0..0x20u32 {
        st32(c, FAKE_C0 + 4 * i, FAKE_CODE + 0x800 + 0x10 * i);
    }
}

// ---- heap (A0h:39h InitHeap, 33h malloc, 34h free) ----
// Blocks: [header: size | used bit 0] [data]; first fit, coalescing on free.

/// InitHeap(address, size): the BIOS malloc arena.
fn init_heap(c: &mut Ctx, a: u32, size: u32) {
    let a = (a + 3) & !3;
    let size = size & !3;
    let k = &mut machine().kernel;
    k.heap_start = a;
    k.heap_end = a + size;
    st32(c, a, size);
    diag::log(format!("InitHeap({a:#010x}, {size:#x})"));
}

/// malloc(n) from the BIOS heap: first fit over blocks with a 4-byte size header (bit 0 = used),
/// merging adjacent free blocks while searching; 0 if out of memory.
fn malloc(c: &mut Ctx, n: u32) -> u32 {
    let (start, end) = (machine().kernel.heap_start, machine().kernel.heap_end);
    if start == 0 {
        return 0;
    }
    let need = ((n + 3) & !3) + 4;
    let mut p = start;
    while p < end {
        let h = ld32(c, p);
        let size = h & !3;
        if size == 0 {
            break;
        }
        if h & 1 == 0 {
            // Coalesce following free blocks.
            let mut sz = size;
            while p + sz < end {
                let nh = ld32(c, p + sz);
                if nh & 1 != 0 || nh & !3 == 0 {
                    break;
                }
                sz += nh & !3;
            }
            if sz >= need {
                if sz - need >= 16 {
                    st32(c, p + need, sz - need);
                    st32(c, p, need | 1);
                } else {
                    st32(c, p, sz | 1);
                }
                return p + 4;
            }
            st32(c, p, sz);
            p += sz;
        } else {
            p += size;
        }
    }
    diag::count("malloc failed (the game probes the largest free block)");
    0
}

/// free(address) back to the BIOS heap.
fn free(c: &mut Ctx, a: u32) {
    if a < 4 {
        return;
    }
    let h = ld32(c, a - 4);
    st32(c, a - 4, h & !1);
}

// ---- printf ----

/// Format the game's printf arguments (%d %x %s %c ...) into a string for the diagnostics log.
fn printf(c: &mut Ctx) -> String {
    let fmt = read_cstr(c, arg(c, 0));
    let mut argi = 1usize;
    let sp = c.gpr(GPR_SP);
    let mut next = |c: &mut Ctx| -> u32 {
        let v = if argi < 4 { c.gpr(GPR_A0 + argi) } else { ld32(c, sp + 4 * argi as u32) };
        argi += 1;
        v
    };
    let mut out = String::new();
    let mut it = fmt.chars().peekable();
    while let Some(ch) = it.next() {
        if ch != '%' {
            out.push(ch);
            continue;
        }
        let mut spec = String::new();
        while let Some(&d) = it.peek() {
            if "-+ #0123456789.lh".contains(d) {
                spec.push(d);
                it.next();
            } else {
                break;
            }
        }
        let width: usize = spec.trim_start_matches(['-', '0', '+', ' ', '#']).split('.').next().and_then(|w| w.parse().ok()).unwrap_or(0);
        let zero = spec.starts_with('0');
        let pad = |s: String| -> String {
            if s.len() >= width {
                s
            } else if zero {
                "0".repeat(width - s.len()) + &s
            } else {
                " ".repeat(width - s.len()) + &s
            }
        };
        match it.next() {
            Some('d') | Some('i') => out += &pad(format!("{}", next(c) as i32)),
            Some('u') => out += &pad(format!("{}", next(c))),
            Some('x') => out += &pad(format!("{:x}", next(c))),
            Some('X') => out += &pad(format!("{:X}", next(c))),
            Some('p') => out += &format!("{:08x}", next(c)),
            Some('c') => out.push(next(c) as u8 as char),
            Some('s') => {
                let a = next(c);
                out += &pad(read_cstr(c, a));
            }
            Some('%') => out.push('%'),
            Some(o) => {
                out.push('%');
                out.push(o);
            }
            None => {}
        }
    }
    out
}
