//! The stable ABI between generated code and the console runtime.
//!
//! The generated crates (`t3-part-NN`, `t3-<variant>`) depend only on this crate. It holds the CPU context
//! (the R3000A register file in a compact layout), p-code operator semantics, the inline RAM
//! fast path and a table of function pointers ([`Host`]) through which everything else (I/O
//! ports, interrupts, the BIOS, the GTE, dispatch) reaches `psx-runtime`. Changing the runtime
//! therefore never rebuilds the generated crates; only changing this file does.

pub mod ops;

use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering::Relaxed};

/// Main RAM: 2 MiB, mirrored four times in the first 8 MiB of every segment (KUSEG/KSEG0/KSEG1).
pub const RAM_SIZE: usize = 0x0020_0000;
/// The data cache used as 1 KiB of scratchpad RAM at 0x1F800000.
pub const SCRATCH_BASE: u32 = 0x1F80_0000;
pub const SCRATCH_SIZE: usize = 0x400;

/// Register file layout (bytes). `tools/gen_rust.py` maps Ghidra's MIPS register offsets onto it.
/// GPR n is at 4*n (r0 reads as zero: the generator never writes it).
pub const REG_PC: usize = 0x80;
pub const REG_LO: usize = 0x84;
pub const REG_HI: usize = 0x88;
/// COP0 Status (SR) and Cause.
pub const REG_SR: usize = 0x8C;
pub const REG_CAUSE: usize = 0x90;
pub const REG_EPC: usize = 0x94;
pub const REG_BYTES: usize = 0x100;

pub const GPR_V0: usize = 2;
pub const GPR_A0: usize = 4;
pub const GPR_T1: usize = 9;
pub const GPR_GP: usize = 28;
pub const GPR_SP: usize = 29;
pub const GPR_FP: usize = 30;
pub const GPR_RA: usize = 31;

/// SR bits: current interrupt enable and the hardware interrupt mask bit (IM2 = INTC).
pub const SR_IEC: u32 = 0x0001;
pub const SR_IM2: u32 = 0x0400;

/// Runtime services, installed once by `psx-runtime`.
pub struct Host {
    /// Loads/stores outside RAM and the scratchpad (I/O ports, BIOS ROM, cache control).
    pub io_read: fn(&mut Ctx, u32, usize) -> u32,
    pub io_write: fn(&mut Ctx, u32, usize, u32),
    /// Run due device events and deliver pending interrupts (called when [`ATTENTION`] is set).
    pub service: fn(&mut Ctx),
    /// HLE handler for a hooked function; true if it handled the call.
    pub hle: fn(&mut Ctx, u32) -> bool,
    /// Run the recompiled function containing an address, or a BIOS entry (0xA0/0xB0/0xC0);
    /// false if there is none.
    pub dispatch: fn(&mut Ctx, u32) -> bool,
    /// `syscall` (EnterCriticalSection / ExitCriticalSection ...), `break`.
    pub syscall: fn(&mut Ctx, u32),
    pub brk: fn(&mut Ctx, u32),
    /// `mtc0`: COP0 register writes (Status changes can unmask a pending interrupt).
    pub mtc0: fn(&mut Ctx, u32, u32),
    /// GTE (COP2): data register read/write, control register read/write, command.
    pub gte_read: fn(&mut Ctx, u32) -> u32,
    pub gte_write: fn(&mut Ctx, u32, u32),
    pub gte_cread: fn(&mut Ctx, u32) -> u32,
    pub gte_cwrite: fn(&mut Ctx, u32, u32),
    pub gte_cmd: fn(&mut Ctx, u32),
    /// Unhandled CALLOTHER intrinsics (counted).
    pub intrinsic: fn(&mut Ctx, &'static str, &[u32]),
    pub log: fn(String),
}

pub static FN_ENTRIES: AtomicU64 = AtomicU64::new(0);
pub static CALLS: AtomicU64 = AtomicU64::new(0);
/// Entries into a function at a non-leader address (see `Ctx::block_miss`).
pub static BLOCK_MISSES: AtomicU64 = AtomicU64::new(0);
pub static UNKNOWN_TARGETS: AtomicU64 = AtomicU64::new(0);
pub static LAST_FN: AtomicU32 = AtomicU32::new(0);
/// Set by the runtime whenever device time has advanced or an interrupt is waiting.
pub static ATTENTION: AtomicBool = AtomicBool::new(false);

/// Bump a statistics counter (one guest thread: a plain load + store is enough).
#[inline(always)]
fn bump(c: &AtomicU64) {
    c.store(c.load(Relaxed).wrapping_add(1), Relaxed);
}

/// Code addresses covered by the HLE hook bitmap (the executable is linked at 0x80010000).
const TEXT_BASE: u32 = 0x8000_0000;
const TEXT_WORDS: usize = RAM_SIZE / 4;

/// One bit per code word: functions routed to `Host::hle`.
static HOOKED: std::sync::OnceLock<Vec<u64>> = std::sync::OnceLock::new();

/// Mark resident function entries handled by HLE (sheets/hle.csv); overlay hooks are compiled in.
pub fn install_hooks(addrs: &[u32]) {
    let mut bits = vec![0u64; TEXT_WORDS / 64];
    for a in addrs {
        let i = (a.wrapping_sub(TEXT_BASE) / 4) as usize;
        if let Some(w) = bits.get_mut(i / 64) {
            *w |= 1 << (i % 64);
        }
    }
    let _ = HOOKED.set(bits);
}

#[inline]
pub fn hooked(addr: u32) -> bool {
    let i = (addr.wrapping_sub(TEXT_BASE) / 4) as usize;
    HOOKED.get().and_then(|b| b.get(i / 64)).is_some_and(|w| w & (1 << (i % 64)) != 0)
}

#[inline]
pub fn get_le(buf: &[u8], off: usize, size: usize) -> u32 {
    match size {
        1 => buf[off] as u32,
        2 => u16::from_le_bytes([buf[off], buf[off + 1]]) as u32,
        _ => u32::from_le_bytes(buf[off..off + 4].try_into().unwrap()),
    }
}
#[inline]
pub fn put_le(buf: &mut [u8], off: usize, size: usize, v: u32) {
    match size {
        1 => buf[off] = v as u8,
        2 => buf[off..off + 2].copy_from_slice(&(v as u16).to_le_bytes()),
        _ => buf[off..off + 4].copy_from_slice(&v.to_le_bytes()),
    }
}

/// Main RAM offset of a CPU address (any segment, 2 MiB mirrored up to 8 MiB), if it is RAM.
#[inline]
pub fn ram_off(addr: u32) -> Option<usize> {
    let phys = addr & 0x1FFF_FFFF;
    (phys < 0x0080_0000).then_some((phys as usize) & (RAM_SIZE - 1))
}

/// One guest CPU.
///
/// The register file lives inline: generated functions take `&mut Ctx`, which tells LLVM nothing
/// else aliases it, so guest registers can stay in host registers across guest memory accesses.
pub struct Ctx {
    pub regs: [u8; REG_BYTES],
    /// Main RAM (RAM_SIZE bytes) and the scratchpad, owned by the runtime's machine.
    pub ram: *mut u8,
    pub scratch: *mut u8,
    pub host: &'static Host,
    /// True while the kernel's interrupt handler runs (no nested interrupts, like the BIOS).
    pub in_irq: bool,
    pub depth: u32,
    /// Set by [`Ctx::call_orig`]: the next entry to this address skips its HLE handler.
    pub bypass: u32,
    /// Targets of the innermost dispatched calls (ring indexed by depth), for diagnostics.
    pub trail: [u32; 64],
    /// Pending tail jump: a jump out of the running function (`j`/`b` to another function,
    /// `jr` through a jump table, falling off its end). The function returns and the nearest
    /// call site continues there ([`Ctx::call`], [`Ctx::settle`]), so jumps consume no host
    /// stack, as on the CPU: a guest loop made of jumps between functions would otherwise
    /// recurse without bound.
    pub next: u32,
}

// SAFETY: guest code runs on exactly one host thread.
unsafe impl Send for Ctx {}

impl Ctx {
    /// A CPU context on the machine's RAM and scratchpad, all registers zero.
    pub fn new(ram: *mut u8, scratch: *mut u8, host: &'static Host) -> Self {
        Ctx { regs: [0; REG_BYTES], ram, scratch, host, in_irq: false, depth: 0, bypass: 0, trail: [0; 64], next: 0 }
    }

    #[inline]
    pub fn ram(&self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.ram, RAM_SIZE) }
    }
    #[inline]
    pub fn scratch(&self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.scratch, SCRATCH_SIZE) }
    }

    // Register space (little endian, like the CPU).
    #[inline] pub fn r(&self, off: usize, size: usize) -> u32 { get_le(&self.regs, off, size) }
    #[inline] pub fn wr(&mut self, off: usize, size: usize, v: u32) { put_le(&mut self.regs, off, size, v) }
    #[inline] pub fn gpr(&self, n: usize) -> u32 { if n == 0 { 0 } else { self.r(4 * n, 4) } }
    #[inline] pub fn set_gpr(&mut self, n: usize, v: u32) { if n != 0 { self.wr(4 * n, 4, v) } }
    #[inline] pub fn sr(&self) -> u32 { self.r(REG_SR, 4) }
    #[inline] pub fn set_sr(&mut self, v: u32) { self.wr(REG_SR, 4, v) }

    /// Guest load. Unaligned accesses (from paired lwl/lwr) are performed bytewise.
    #[inline]
    pub fn ld(&mut self, addr: u32, size: usize) -> u32 {
        if let Some(o) = ram_off(addr) {
            if o + size <= RAM_SIZE {
                return get_le(self.ram(), o, size);
            }
            let mut v = 0;
            for i in 0..size {
                v |= (self.ram()[(o + i) & (RAM_SIZE - 1)] as u32) << (8 * i);
            }
            return v;
        }
        let p = addr & 0x1FFF_FFFF;
        if p.wrapping_sub(SCRATCH_BASE) < SCRATCH_SIZE as u32 && (p - SCRATCH_BASE) as usize + size <= SCRATCH_SIZE {
            return get_le(self.scratch(), (p - SCRATCH_BASE) as usize, size);
        }
        (self.host.io_read)(self, addr, size)
    }

    #[inline]
    pub fn st(&mut self, addr: u32, size: usize, v: u32) {
        if let Some(o) = ram_off(addr) {
            if o + size <= RAM_SIZE {
                return put_le(self.ram(), o, size, v);
            }
            for i in 0..size {
                self.ram()[(o + i) & (RAM_SIZE - 1)] = (v >> (8 * i)) as u8;
            }
            return;
        }
        let p = addr & 0x1FFF_FFFF;
        if p.wrapping_sub(SCRATCH_BASE) < SCRATCH_SIZE as u32 && (p - SCRATCH_BASE) as usize + size <= SCRATCH_SIZE {
            return put_le(self.scratch(), (p - SCRATCH_BASE) as usize, size, v);
        }
        (self.host.io_write)(self, addr, size, v)
    }

    /// Called at the top of every generated function: bookkeeping, device service and the HLE
    /// check. Returns true if an HLE handler fully handled the call.
    #[inline]
    pub fn enter(&mut self, addr: u32, entry: u32) -> bool {
        bump(&FN_ENTRIES);
        LAST_FN.store(addr, Relaxed);
        // Consume the bypass before interrupt delivery can run other guest code.
        let bypass = self.bypass == addr;
        if bypass {
            self.bypass = 0;
        }
        if ATTENTION.load(Relaxed) {
            (self.host.service)(self);
        }
        if bypass || entry != addr || !hooked(addr) {
            return false;
        }
        (self.host.hle)(self, addr)
    }

    /// `enter` for overlay code: overlays share addresses, so whether this function is hooked is
    /// decided by the generator per (variant, address) and passed in, not looked up by address.
    #[inline]
    pub fn enter_ovl(&mut self, addr: u32, entry: u32, hooked: bool) -> bool {
        bump(&FN_ENTRIES);
        LAST_FN.store(addr, Relaxed);
        let bypass = self.bypass == addr;
        if bypass {
            self.bypass = 0;
        }
        if ATTENTION.load(Relaxed) {
            (self.host.service)(self);
        }
        if bypass || entry != addr || !hooked {
            return false;
        }
        (self.host.hle)(self, addr)
    }

    /// Loop back-edge: service devices and deliver pending interrupts, as the CPU would between
    /// any two instructions. Without this, a loop that waits for a flag set by an interrupt
    /// handler (`VSync`) never sees the interrupt, since it enters no function.
    #[inline(always)]
    pub fn poll(&mut self) {
        if ATTENTION.load(Relaxed) {
            (self.host.service)(self);
        }
    }

    /// A function was entered at an address that isn't one of its block leaders (a computed
    /// jump the generator didn't know about). Logged; the call returns without running code.
    #[cold]
    pub fn block_miss(&mut self, func: u32, pc: u32) {
        BLOCK_MISSES.fetch_add(1, Relaxed);
        (self.host.log)(format!("mid-block entry {pc:#010x} in function {func:#010x} (not a block leader)"));
    }

    /// Jump out of the running function: the caller returns right after this.
    #[inline(always)]
    pub fn tail(&mut self, target: u32) {
        self.next = target;
    }

    /// After a direct call: run the tail jump the callee left pending, if any (its eventual
    /// `jr ra` returns here, like the callee's own return would have).
    #[inline(always)]
    pub fn settle(&mut self) {
        if self.next != 0 {
            let t = std::mem::take(&mut self.next);
            self.call(t);
        }
    }

    /// Call through the dispatch table (indirect calls, BIOS calls), then follow the tail jumps
    /// the callee leaves pending until code returns.
    pub fn call(&mut self, mut target: u32) {
        loop {
            self.call_one(target);
            if self.next == 0 {
                return;
            }
            target = std::mem::take(&mut self.next);
        }
    }

    /// One dispatched call: depth bookkeeping and the diagnostics trail, then `Host::dispatch`.
    fn call_one(&mut self, target: u32) {
        bump(&CALLS);
        if self.depth > 20_000 {
            let chain: Vec<String> = (0..64u32)
                .map(|i| self.trail[(self.depth.wrapping_sub(i) & 63) as usize])
                .map(|t| format!("{t:08x}"))
                .collect();
            (self.host.log)(format!(
                "call depth limit hit at {target:#010x} (in_irq {}); innermost calls: {}",
                self.in_irq,
                chain.join(" ")
            ));
            return;
        }
        self.depth += 1;
        self.trail[(self.depth & 63) as usize] = target;
        let found = (self.host.dispatch)(self, target);
        self.depth -= 1;
        if !found {
            UNKNOWN_TARGETS.fetch_add(1, Relaxed);
            (self.host.log)(format!("unknown call target {target:#010x}"));
        }
    }

    /// From an HLE handler: run the original recompiled function at `addr`.
    pub fn call_orig(&mut self, addr: u32) {
        self.bypass = addr;
        self.call(addr);
        self.bypass = 0;
    }

    /// Call a guest function with up to 4 register arguments; returns v0. `ra` is preserved.
    pub fn call_guest(&mut self, addr: u32, args: &[u32]) -> u32 {
        for (i, a) in args.iter().enumerate().take(4) {
            self.set_gpr(GPR_A0 + i, *a);
        }
        let ra = self.gpr(GPR_RA);
        self.call(addr);
        self.set_gpr(GPR_RA, ra);
        self.gpr(GPR_V0)
    }

    // Coprocessor access from generated code.
    #[inline] pub fn mtc0(&mut self, reg: u32, v: u32) { (self.host.mtc0)(self, reg, v) }
    #[inline] pub fn gte_read(&mut self, n: u32) -> u32 { (self.host.gte_read)(self, n) }
    #[inline] pub fn gte_write(&mut self, n: u32, v: u32) { (self.host.gte_write)(self, n, v) }
    #[inline] pub fn gte_cread(&mut self, n: u32) -> u32 { (self.host.gte_cread)(self, n) }
    #[inline] pub fn gte_cwrite(&mut self, n: u32, v: u32) { (self.host.gte_cwrite)(self, n, v) }
    #[inline] pub fn gte_cmd(&mut self, op: u32) { (self.host.gte_cmd)(self, op) }
    #[inline] pub fn syscall(&mut self, code: u32) { (self.host.syscall)(self, code) }
    #[inline] pub fn brk(&mut self, code: u32) { (self.host.brk)(self, code) }

    /// Other CALLOTHER intrinsics.
    pub fn intrinsic(&mut self, name: &'static str, args: &[u32]) -> u32 {
        (self.host.intrinsic)(self, name, args);
        0
    }
}
