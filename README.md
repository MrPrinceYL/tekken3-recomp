# Tekken3Decomp: Tekken 3 (SLUS-00402, PlayStation), Spreadsheet Method

The CSVs in `sheets/` are the **single source of truth** for all of the game's code: the
executable `SLUS_004.02` and the ten code overlays it loads from `TEKKEN3.BNS`. Everything else
is a projection: `src/` (Ghidra C, for reading) and `rust/` (compilable Rust, for running) are
generated from the sheets and never edited by hand.

```
Tekken 3 (USA).cue / (Track 1).bin / (Track 2).bin / (Track 3).bin
   │ tools/psx_extract.py    (ISO9660 over raw 2352-byte MODE2 sectors → files + disc_files.csv)
   ▼
../Tekken3/extracted/files/TEKKEN3/  SLUS_004.02, TEKKEN3.BNS (303-file archive), TEKKEN3.XAS (XA/STR)
   │ tools/find_stubs.py     (names the BIOS call stubs A0h/B0h/C0h → symbols.csv)
   │ tools/bns_overlays.py   (BNS table of contents at 0x80024400 → the 10 code files and their load
   │                          addresses; one ELF per code variant: resident.elf, overlays/<variant>.elf)
   ▼
tools/run_ghidra.sh  ── ghidra-cli ──►  ../Tekken3/ghidra/TEKKEN3.gpr (one program per variant)
   │ SetGp.java (gp = 0x8009B9A8) → ApplySymbols.java → Analyze.java → FixNoReturn.java →
   │ CreateGapFunctions.java → CleanFunctions.java (overlay ranges) → ExportPcode.java → ExportSheets.java
   ▼
../Tekken3/export/<variant>/ ──tools/build_sheets.py──► sheets/*.csv ──► src/raw_c, src/units (C)
                                                           └─tools/gen_rust.py──► rust/ (Bevy app)
```

## Playing

Run **`play.bat`**. The first run builds everything (several minutes), later runs start in
seconds. The disc image is read from `T3_DISC`, which defaults to
`E:\Decompilation\Game\Tekken 3 (USA).cue` (the .cue with all three tracks).

- Keyboard and gamepads work at once. F2 rebinds controls (`%APPDATA%\Tekken3Decomp\controls.json`).
  Default keyboard: arrows / WASD = D-pad, X or Space = Cross, C = Circle, Z = Square,
  V = Triangle, Q / E = L1 / R1, 1 / 3 = L2 / R2, Enter = Start, Tab / Right Shift = Select.
  A second gamepad becomes the controller in port 2.
- P opens the settings: volume, window mode, gamma, VSync, sharp or smooth picture and the FPS
  counter. F1 shows the debug overlay, F3 the whole video memory. F11 or Alt+Enter toggles
  borderless fullscreen.
- The memory card in slot 1 is `rust/memcard/slot1.mcd` (a standard 128 KiB raw card image that
  other emulators can read; override with `T3_MEMCARD`). `T3_MEMCARD2` inserts a card in slot 2.
- `rust/t3_trace.log` (written every 5 s) is the diagnostics log: frame pacing, interrupts,
  CD-ROM / SPU / pad / memory card activity, GPU state and command counts, which overlay is in
  use, and the game's own `printf` output. `rust/t3_vram.bin` is a video memory snapshot
  (1024x512, 16-bit) taken at the same time. If something goes wrong, send both.

## Rebuilding from the disc

You need Python 3, Ghidra 12.1, ghidra-cli and a Rust toolchain. The work folder (`..\Tekken3`,
next to this folder) holds the extracted disc, the Ghidra project and the raw export.

```bat
set BIN=E:\Decompilation\Game\Tekken 3 (USA) (Track 1).bin
set W=E:\Decompilation\Decomps\Tekken3
cd tools
python psx_extract.py "%BIN%" %W%\extracted
python find_stubs.py %W%\extracted\files\TEKKEN3\SLUS_004.02 %W%\extracted\symbols.csv
python bns_overlays.py %W%\extracted
set GHIDRA=E:\Decompilation\Tools\ghidra-cli\target\release\ghidra.exe
set T3_WORK=%W%
bash run_ghidra.sh
python build_sheets.py && python gen_rust.py
```

`run_ghidra.sh` is resumable: a program that is already analyzed (`ghidra/<program>.analyzed`)
is only exported again; name variants to process just those (`bash run_ghidra.sh pkg301`).

## The executable and its overlays

`SLUS_004.02` is a PS-X EXE of 0x121000 bytes loaded at 0x80010000, entry `__start` 0x80079C70,
gp 0x8009B9A8, BSS 0x8009B9A8..0x800B0548, stack at 0x801FFFF0. It was linked with PsyQ: Namco's
game code first (0x80028BA0..0x80079C70), then the startup code and the Sony libraries. It has no
symbols; the BIOS call stubs are named from the kernel's function tables, a few functions by hand
(`sheets/manual_names.csv`, with the evidence), and library code is assigned to libraries by the
hardware it touches.

Everything from 0x800B0548 up is **overlay space**. `main` (0x80028BA0) runs the executable's own
init code there once, then loops over a game-state switch whose handlers mostly live in code that
the game loads from `TEKKEN3.BNS` over that space. The BNS archive's table of contents is compiled
into the executable at 0x80024400 (303 × {sector offset, byte size}); `bns_read` (0x8006BF20) adds
the sector offset to the archive's LBA. Ten of its files are code, linked to one of two addresses
(found by checking which base makes each file's `jal` targets land on function prologues):

| Variant | Source | Load address | Size |
|---|---|---|---|
| `init` | the executable's own code at 0x800B0548 (boot/init) | 0x800B0548 | 0x7A8 |
| `ovl005`..`ovl008` | BNS files 5..8 (overlays) | 0x800B0548 | 0x4500..0x8618 |
| `pkg000`, `pkg009`..`pkg011`, `pkg301`, `pkg302` | BNS files 0, 9, 10, 11, 301, 302 (mode packages: code + data, loaded at the start of the heap) | 0x800B8D58 | 0x12B20..0x8B38C |

Each variant is analyzed as its own Ghidra program (the resident executable plus that variant;
everything else uninitialized), so Ghidra never sees two overlays at once. The resident code calls
fixed overlay addresses that belong to whichever overlay is loaded; in a variant's program, those
calls stay only if the target is a plausible function start in *that* variant (otherwise Ghidra
would start functions in the middle of this variant's code).

## Sheets

| Sheet | Key | Contents |
|---|---|---|
| `meta.csv` | `key` | Game ID, executable, entry point, gp, memory map, BNS table of contents, toolchain |
| `variants.csv` | `variant` | The code variants: kind, BNS file, load address, end, SHA-1, function / instruction counts |
| `functions.csv` | `variant,addr` | name, size, module (game / psyq), **unit, status, owner**, fan-in/out, signature, C path, notes |
| `units.csv` | `variant,unit` | Work partitions: `game/seg_XXXXXXXX` (8 KiB address ranges of resident game code), `psyq/<library>`, `<variant>/seg_XXXXXXXX` (overlay code), with status roll-ups |
| `manual_names.csv` | `variant,addr` | Names identified by hand, with the evidence (always applied by build_sheets.py) |
| `symbols.csv` | `addr` | BIOS call stubs (table, function number) and `__start` |
| `hle.csv` | `name` | Functions replaced by high-level emulation in the Rust runtime |
| `calls.csv` | `variant,caller,callee` | Static call graph |
| `instructions.csv` | `variant,addr` | Every instruction: owning function, bytes, disassembly, **delay-slot flag**, **raw p-code semantics** |
| `memory.csv` | `section,addr` | The executable image (`exe`, as the BIOS loads it) and every variant's bytes, 64 bytes/row hex |
| `registers.csv` | `name` | Ghidra's MIPS register layout (offsets used by p-code `R` varnodes) |
| `strings.csv` | `variant,addr` | Defined strings + referencing functions |
| `globals.csv` | `variant,addr` | Data labels, types, sizes, xref counts |
| `sections.csv` | `name` | Memory blocks of the resident program |
| `disc_files.csv` | `path` | Every file on the disc with LBA, size and form |
| `bns_toc.csv` | `index` | The 303 files of TEKKEN3.BNS: sector, offset, size, whether it is code and its load address |

`instructions.csv`, `memory.csv`, `variants.csv`, `registers.csv` and `meta.csv` fully describe
the program, and they are what `gen_rust.py` consumes. P-code varnodes are written
`<space><hexoffset>:<size>`, where the space is `R` register, `U` temporary, `C` constant or `M`
RAM. A MIPS branch's p-code already contains its delay slot (Ghidra inlines it); delay-slot rows
are flagged and only emitted on their own when code jumps straight into one.

### Status lifecycle (`functions.csv:status`)
`raw` (auto name `FUN_…`) → `named` → `typed` → `clean` → `verified`.
To see what is left, read the per-status columns in `units.csv`.

## Rust / Bevy (`rust/`)

| Crate | What |
|---|---|
| `psx-core` | Stable ABI for generated code: R3000A context (compact register file), p-code ops with R3000A division semantics, inline RAM/scratchpad access, and the `Host` function table |
| `psx-runtime` | The PlayStation behind `Host`: interrupt controller, DMA, root counters, GPU (software rasterizer on 1 MiB VRAM), SPU (24 ADPCM voices, ADSR, reverb, CD input), CD-ROM controller (cue/bin, XA-ADPCM, CD-DA), MDEC, GTE, controller port, and the HLE BIOS kernel; the dispatcher that picks the loaded overlay |
| `recomp/part_00..07` | **Generated.** Resident code: one `pub fn f_<ADDR>(c, entry)` per function, from `instructions.csv`, with one match arm per basic block. Loop back-edges poll for interrupts |
| `recomp/<variant>` | **Generated.** One crate per overlay / mode package: `f_<ADDR>_<variant>` |
| `t3-recomp` | Dispatch tables, executable image and variant images (`mem/`), boot |
| `t3-bevy` | Bevy 0.19 app: runs the game, shows its display area on a quad under a 3D orthographic camera, plays the SPU output and feeds keyboard / gamepad input into the controller ports |

### How the console is reproduced

- **CPU**: static recompilation of every instruction's p-code. Calls to the BIOS (`jr t2` to
  0xA0/0xB0/0xC0) go to the HLE kernel. `syscall` implements Enter/ExitCriticalSection.
- **Overlays**: a call is linked directly only when the target can't be anything else (a resident
  function, or a function of the caller's own variant). Every other call into overlay space goes
  through the dispatcher, which runs the function of the variant whose bytes are in RAM at that
  moment (if several variants have identical bytes there, the one whose whole code is loaded).
  Overlays get into RAM exactly as on the console: the game reads them from the disc image.
- **Time**: device time is host time in CPU cycles (33.8688 MHz). Vertical blank at the NTSC rate
  (263 lines of 2152 cycles), root counters, CD sector timing (75/150 sectors per second), SPU
  output (44100 Hz) all follow it, so the game runs at the console's speed.
- **Interrupts**: as the BIOS does it: the queued handler chains (SysEnqIntRP) run first, then root
  counter events, then the game's exit hook (libetc's dispatcher, installed with HookEntryInt and a
  setjmp buffer) runs on its own stack; its ReturnFromException unwinds back and the interrupted
  state is restored.
- **Controllers**: the BIOS pad driver (InitPAD / StartPAD) is emulated: a digital pad answers on
  each connected port and the buffers are filled every vertical blank.
- **HLE functions** (`sheets/hle.csv`): libetc's `v_wait` and `VSync(-1)`. Their timeouts count
  loop iterations; on a fast host they would expire at once, so they are given the console's
  real-time equivalent.
