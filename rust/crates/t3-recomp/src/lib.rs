//! Boot glue for the recompiled Tekken 3: the generated dispatch table (`table.rs`), the executable
//! image, and the state the BIOS leaves behind when it starts a PS-X EXE.

pub mod table;

use psx_core::{Ctx, GPR_SP, REG_SR};
use psx_runtime::{diag, kernel, machine, Shared};

pub use table::FUNCTION_COUNT;

/// The disc image (.cue with all three tracks): `T3_DISC`, or the default location of the rip.
pub fn disc_path() -> String {
    if let Ok(p) = std::env::var("T3_DISC") {
        return p;
    }
    r"E:\Decompilation\Game\Tekken 3 (USA).cue".into()
}

/// Create the machine, load the executable and prepare the CPU at its entry point.
pub fn boot() -> (Ctx, Shared) {
    let shared = psx_runtime::create(&disc_path(), &table::parts(), table::VARIANTS, table::NAMES, table::HLE);
    let m = machine();
    for (addr, data) in table::SECTIONS {
        let off = (*addr & 0x1F_FFFF) as usize;
        m.ram[off..off + data.len()].copy_from_slice(data);
    }
    let mut c = psx_runtime::new_ctx();
    kernel::install_fake_tables(&mut c);
    // As left by the BIOS's Exec(): stack from the EXE header, interrupts enabled in SR (the
    // interrupt mask register starts empty, so nothing arrives until the game sets it up).
    c.set_gpr(GPR_SP, 0x801F_FFF0);
    c.wr(REG_SR, 4, 0x0000_0401);
    diag::log(format!("boot: {} functions, entry {:#010x}", table::FUNCTION_COUNT, table::ENTRY_POINT));
    (c, shared)
}

/// Run the game on this thread (does not return while the game runs).
pub fn run(c: &mut Ctx) {
    psx_runtime::start_ticker();
    c.call(table::ENTRY_POINT);
    diag::log("the game's entry point returned".into());
    loop {
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}

/// Name of the resident function containing `addr` (diagnostics).
pub fn function_name(addr: u32) -> Option<&'static str> {
    psx_runtime::function_name(addr)
}
