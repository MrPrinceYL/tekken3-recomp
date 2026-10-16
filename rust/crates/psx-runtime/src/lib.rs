//! The PlayStation behind `psx_core::Host`: the hardware the recompiled game talks to (interrupt
//! controller, DMA, root counters, GPU, SPU, CD-ROM, MDEC, controller port), the GTE and a
//! high-level emulation of the BIOS kernel (A0h/B0h/C0h function tables, events, the interrupt
//! dispatcher, memory card file system).
//!
//! Everything here runs on the guest CPU thread; the Bevy front end only touches the [`Shared`]
//! parts (finished frames, audio samples, controller state).
//!
//! Time: the guest runs as fast as the host allows. Device time is host time converted to CPU
//! cycles (33.8688 MHz); a ticker thread raises `psx_core::ATTENTION` every millisecond and the
//! generated code calls [`service`] at the next function entry or loop back-edge, which advances
//! the devices to the current time and takes a pending interrupt if the CPU has them enabled.

pub mod audio;
pub mod bus;
pub mod cdrom;
pub mod diag;
pub mod disc;
pub mod dma;
pub mod gpu;
pub mod gte;
pub mod kernel;
pub mod mdec;
pub mod memcard;
pub mod pad;
pub mod raster;
pub mod sio;
pub mod spu;
pub mod timers;
pub mod xa;

pub use psx_core::{Ctx, Host, BLOCK_MISSES, CALLS, FN_ENTRIES, LAST_FN, UNKNOWN_TARGETS};
use psx_core::{ATTENTION, SR_IEC, SR_IM2};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::Arc;
use std::time::Instant;

/// CPU clock (Hz).
pub const CPU_HZ: u64 = 33_868_800;
/// NTSC: 263 scanlines of 3413 GPU clocks (53.693175 MHz) = 2152.5 CPU cycles each.
pub const CYCLES_PER_LINE: u64 = 2152;
pub const LINES_PER_FRAME: u64 = 263;
pub const CYCLES_PER_FRAME: u64 = CYCLES_PER_LINE * LINES_PER_FRAME;

pub const IRQ_VBLANK: u32 = 0;
pub const IRQ_GPU: u32 = 1;
pub const IRQ_CDROM: u32 = 2;
pub const IRQ_DMA: u32 = 3;
pub const IRQ_TMR0: u32 = 4;
pub const IRQ_TMR1: u32 = 5;
pub const IRQ_TMR2: u32 = 6;
pub const IRQ_SIO: u32 = 7;
pub const IRQ_SPU: u32 = 9;

/// End of the always-resident code; above it, code variants (overlays) are loaded at run time.
pub const RESIDENT_END: u32 = 0x800B_0548;

/// Vertical blanks delivered so far.
pub static VBLANKS: AtomicU64 = AtomicU64::new(0);

/// What the Bevy front end shares with the machine.
#[derive(Clone)]
pub struct Shared {
    pub frames: Arc<gpu::FrameShared>,
    pub audio: Arc<audio::AudioShared>,
    pub pad: Arc<pad::PadShared>,
}

/// Code that is loaded over part of RAM at run time (an overlay): its linked address, its bytes
/// as they come from the disc and its recompiled functions `(start, end, fn)`.
pub struct Variant {
    pub name: &'static str,
    pub base: u32,
    pub image: &'static [u8],
    pub funcs: &'static [(u32, u32, fn(&mut Ctx, u32))],
}

impl Variant {
    /// This variant's function containing `addr` (start, end, entry point), if any.
    fn func(&self, addr: u32) -> Option<(u32, u32, fn(&mut Ctx, u32))> {
        let i = self.funcs.partition_point(|(s, _, _)| *s <= addr);
        (i > 0).then(|| self.funcs[i - 1]).filter(|(s, e, _)| addr >= *s && addr < *e)
    }

    /// True if RAM holds this variant's bytes over `[s, e)`.
    fn resident(&self, ram: &[u8], s: u32, e: u32) -> bool {
        let (ro, io) = (((s & 0x1F_FFFF) as usize), (s - self.base) as usize);
        let n = (e - s) as usize;
        io + n <= self.image.len() && ram[ro..ro + n] == self.image[io..io + n]
    }

    /// True if RAM holds all of this variant's code.
    fn fully_resident(&self, ram: &[u8]) -> bool {
        self.funcs.iter().all(|&(s, e, _)| self.resident(ram, s, e))
    }
}

pub struct Machine {
    pub ram: Box<[u8]>,
    pub scratch: Box<[u8]>,
    pub istat: u32,
    pub imask: u32,
    pub start: Instant,
    pub dma: dma::Dma,
    pub timers: timers::Timers,
    pub gpu: gpu::Gpu,
    pub cd: cdrom::Cdrom,
    pub spu: spu::Spu,
    pub mdec: mdec::Mdec,
    pub sio: sio::Sio,
    pub gte: gte::Gte,
    pub kernel: kernel::Kernel,
    pub next_vblank: u64,
    /// MDEC finished decoding during a DMA0 transfer: run a waiting DMA1 afterwards.
    pub mdec_kick: bool,
    pub shared: Shared,
    funcs: Vec<(u32, u32, fn(&mut Ctx, u32))>,
    variants: &'static [Variant],
    last_variant: [std::cell::Cell<usize>; 2],
    names: Vec<(u32, &'static str)>,
    hle: HashMap<u32, &'static str>,
}

static mut MACHINE: *mut Machine = std::ptr::null_mut();

/// The machine. Only the guest CPU thread (and boot, before it starts) may use it.
#[allow(static_mut_refs)]
pub fn machine() -> &'static mut Machine {
    unsafe {
        assert!(!MACHINE.is_null(), "machine not created");
        &mut *MACHINE
    }
}

impl Machine {
    /// Current device time in CPU cycles since boot.
    #[inline]
    pub fn now(&self) -> u64 {
        let ns = self.start.elapsed().as_nanos();
        (ns * CPU_HZ as u128 / 1_000_000_000) as u64
    }

    /// Request an interrupt (I_STAT bit); delivered at the next service point.
    #[inline]
    pub fn raise(&mut self, irq: u32) {
        self.istat |= 1 << irq;
        ATTENTION.store(true, Relaxed);
    }

    /// True if an interrupt is requested (I_STAT) and enabled (I_MASK).
    pub fn irq_pending(&self) -> bool {
        self.istat & self.imask & 0x7FF != 0
    }

    /// Name of the resident function containing `addr` (diagnostics).
    pub fn function_name(&self, addr: u32) -> Option<&'static str> {
        let i = self.names.partition_point(|(a, _)| *a <= addr);
        (i > 0).then(|| self.names[i - 1].1)
    }

    /// Recompiled function containing `addr`: resident code first, then the overlay variant that is
    /// in RAM now. This is the dispatcher every indirect call and tail jump goes through.
    fn lookup(&self, addr: u32) -> Option<fn(&mut Ctx, u32)> {
        let i = self.funcs.partition_point(|(s, _, _)| *s <= addr);
        // Function spans can nest (a function whose code wraps around another one): look back
        // past the nearest start until a span holds the address.
        for &(s, e, f) in self.funcs[..i].iter().rev().take(64) {
            if addr >= s && addr < e {
                return Some(f);
            }
        }
        self.lookup_variant(addr)
    }

    /// The function at `addr` of the code variant that is in RAM now: the one whose bytes over
    /// that function match RAM. If several variants share identical bytes there, the one whose
    /// whole code is in RAM wins (its direct calls to its other functions must be right too).
    fn lookup_variant(&self, addr: u32) -> Option<fn(&mut Ctx, u32)> {
        let mut hit: Option<(&Variant, fn(&mut Ctx, u32))> = None;
        let mut ties = 0;
        for v in self.variants {
            if let Some((s, e, f)) = v.func(addr) {
                if v.resident(&self.ram, s, e) {
                    if hit.is_none() {
                        hit = Some((v, f));
                    }
                    ties += 1;
                }
            }
        }
        if ties > 1 {
            for v in self.variants {
                if let Some((s, e, f)) = v.func(addr) {
                    if v.resident(&self.ram, s, e) && v.fully_resident(&self.ram) {
                        return Some(f);
                    }
                }
            }
        }
        if let Some((v, f)) = hit {
            // Log which overlay is in use whenever it changes (per load address).
            let slot = if v.base == RESIDENT_END { &self.last_variant[0] } else { &self.last_variant[1] };
            if slot.get() != v.name.as_ptr() as usize {
                slot.set(v.name.as_ptr() as usize);
                diag::log(format!("overlay in use at {:#010x}: {}", v.base, v.name));
            }
            return Some(f);
        }
        None
    }
}

/// Create the machine: RAM, devices, the disc image and the shared front-end state.
/// `parts` are the generated function tables, `hle` the hooked functions (sheets/hle.csv).
pub fn create(
    disc_path: &str,
    parts: &[&'static [(u32, u32, fn(&mut Ctx, u32))]],
    variants: &'static [Variant],
    names: &'static [(u32, &'static str)],
    hle: &'static [(u32, &'static str)],
) -> Shared {
    let shared = Shared {
        frames: Arc::new(gpu::FrameShared::default()),
        audio: Arc::new(audio::AudioShared::new()),
        pad: Arc::new(pad::PadShared::default()),
    };
    let disc = match disc::Disc::open(disc_path) {
        Ok(d) => {
            diag::log(format!("disc: {} ({} sectors, {} tracks)", disc_path, d.total_sectors(), d.tracks.len()));
            Some(d)
        }
        Err(e) => {
            diag::log(format!("disc: cannot open {disc_path}: {e}"));
            None
        }
    };
    let mut funcs: Vec<_> = parts.iter().flat_map(|p| p.iter().copied()).collect();
    funcs.sort_by_key(|f| f.0);
    let m = Box::new(Machine {
        ram: vec![0u8; psx_core::RAM_SIZE].into_boxed_slice(),
        scratch: vec![0u8; psx_core::SCRATCH_SIZE].into_boxed_slice(),
        istat: 0,
        imask: 0,
        start: Instant::now(),
        dma: dma::Dma::default(),
        timers: timers::Timers::default(),
        gpu: gpu::Gpu::new(),
        cd: cdrom::Cdrom::new(disc),
        spu: spu::Spu::new(),
        mdec: mdec::Mdec::new(),
        sio: sio::Sio::new(shared.pad.clone()),
        gte: gte::Gte::default(),
        kernel: kernel::Kernel::new(),
        next_vblank: CYCLES_PER_FRAME,
        mdec_kick: false,
        shared: shared.clone(),
        funcs,
        variants,
        last_variant: Default::default(),
        names: names.to_vec(),
        hle: hle.iter().copied().collect(),
    });
    unsafe { MACHINE = Box::into_raw(m) };
    // Only resident code is hooked by address; overlay functions carry their hook in the
    // generated code (overlays share addresses).
    psx_core::install_hooks(&hle.iter().map(|h| h.0).filter(|&a| a < RESIDENT_END).collect::<Vec<_>>());
    shared
}

/// The guest CPU context for the machine (call after [`create`]).
pub fn new_ctx() -> Ctx {
    let m = machine();
    Ctx::new(m.ram.as_mut_ptr(), m.scratch.as_mut_ptr(), &HOST)
}

/// Start the ticker that makes the CPU thread service devices every millisecond.
pub fn start_ticker() {
    std::thread::Builder::new()
        .name("psx-ticker".into())
        .spawn(|| {
            #[cfg(windows)]
            unsafe {
                windows_time_period();
            }
            loop {
                std::thread::sleep(std::time::Duration::from_micros(1000));
                ATTENTION.store(true, Relaxed);
            }
        })
        .expect("spawn ticker");
}

#[cfg(windows)]
unsafe fn windows_time_period() {
    #[link(name = "winmm")]
    unsafe extern "system" {
        fn timeBeginPeriod(period: u32) -> u32;
    }
    unsafe { timeBeginPeriod(1) };
}

pub static HOST: Host = Host {
    io_read: bus::io_read,
    io_write: bus::io_write,
    service,
    hle: hle_call,
    dispatch,
    syscall: kernel::syscall,
    brk: kernel::brk,
    mtc0,
    gte_read: |_, n| machine().gte.read_data(n),
    gte_write: |_, n, v| machine().gte.write_data(n, v),
    gte_cread: |_, n| machine().gte.read_ctrl(n),
    gte_cwrite: |_, n, v| machine().gte.write_ctrl(n, v),
    gte_cmd: |_, op| machine().gte.command(op),
    intrinsic,
    log: diag::log,
};

/// CALLOTHER p-code ops the generator has no translation for: counted in the trace.
fn intrinsic(_c: &mut Ctx, name: &'static str, args: &[u32]) {
    diag::count(&format!("intrinsic {name}"));
    let _ = args;
}

/// `mtc0`: Status (12; may unmask a pending interrupt), Cause (13; software interrupt bits), EPC (14).
fn mtc0(c: &mut Ctx, reg: u32, v: u32) {
    match reg {
        12 => {
            c.set_sr(v);
            if machine().irq_pending() {
                ATTENTION.store(true, Relaxed);
            }
        }
        13 => {
            // Only the two software interrupt bits are writable.
            let cause = c.r(psx_core::REG_CAUSE, 4);
            c.wr(psx_core::REG_CAUSE, 4, (cause & !0x300) | (v & 0x300));
        }
        14 => c.wr(psx_core::REG_EPC, 4, v),
        _ => diag::count(&format!("mtc0 r{reg}")),
    }
}

/// Address of a hooked function (sheets/hle.csv) by name.
pub fn hle_address(name: &str) -> Option<u32> {
    machine().hle.iter().find(|(_, n)| **n == name).map(|(a, _)| *a)
}

/// Run the HLE handler registered for `addr` (sheets/hle.csv); false lets the original run.
fn hle_call(c: &mut Ctx, addr: u32) -> bool {
    let Some(name) = machine().hle.get(&addr).copied() else { return false };
    kernel::hle(c, addr, name)
}

/// `Host::dispatch`: BIOS table calls (0xA0 / 0xB0 / 0xC0), recompiled code (any RAM mirror is
/// normalised to KSEG0), else the fake kernel stub handler.
fn dispatch(c: &mut Ctx, addr: u32) -> bool {
    match addr {
        0xA0 | 0xB0 | 0xC0 | 0x8000_00A0 | 0x8000_00B0 | 0x8000_00C0 | 0xA000_00A0 | 0xA000_00B0 | 0xA000_00C0 => {
            kernel::bios_call(c, addr & 0xFF);
            return true;
        }
        _ => {}
    }
    let a = if addr & 0x1FFF_FFFF < 0x0080_0000 { (addr & 0x001F_FFFF) | 0x8000_0000 } else { addr };
    match machine().lookup(a) {
        Some(f) => {
            f(c, a);
            true
        }
        None => kernel::fake_call(c, a),
    }
}

/// Advance every device to the current time, then take a pending interrupt if enabled.
pub fn service(c: &mut Ctx) {
    ATTENTION.store(false, Relaxed);
    let m = machine();
    let now = m.now();
    // Vertical blank (and everything that is clocked by frames).
    if now >= m.next_vblank {
        if now - m.next_vblank > 4 * CYCLES_PER_FRAME {
            // The host stalled (window drag, long load): don't replay the missed frames.
            m.next_vblank = now;
        }
        m.next_vblank += CYCLES_PER_FRAME;
        m.raise(IRQ_VBLANK);
        VBLANKS.fetch_add(1, Relaxed);
        m.gpu.vblank(&m.shared.frames, now);
        m.timers.vblank(now);
        diag::tick(m);
    }
    timers::update(m, now);
    cdrom::update(m, now);
    dma::update(m, now);
    spu::update(m, now);
    sio::update(m, now);
    kernel::update(m, now);
    if !c.in_irq && (m.irq_pending() || m.kernel.wants_irq(now)) {
        let sr = c.sr();
        if sr & SR_IEC != 0 && sr & SR_IM2 != 0 {
            kernel::interrupt(c);
        }
    }
}

/// Address of the instruction a function name maps to (for diagnostics).
pub fn function_name(addr: u32) -> Option<&'static str> {
    machine().function_name(addr)
}
