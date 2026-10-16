"""Build the Spreadsheet-Method tables from the raw Ghidra exports.

Inputs  (../../Tekken3/export/<variant>/): functions_raw.csv calls.csv strings.csv globals.csv
                                           sections.csv instructions.csv registers.csv raw_c/*.c
        (../../Tekken3/extracted/):        symbols.csv (find_stubs.py), disc_files.csv
                                           (psx_extract.py), bns_toc.csv + overlays.csv +
                                           overlays/*.bin (bns_overlays.py), files/
Outputs (sheets/):  meta.csv variants.csv functions.csv units.csv symbols.csv calls.csv
                    strings.csv globals.csv sections.csv instructions.csv memory.csv
                    registers.csv disc_files.csv bns_toc.csv
        (src/raw_c/<variant>/, src/units/): the Ghidra C, one file per function and per unit

Tekken 3's code comes in variants (sheets/variants.csv): the resident executable and the code
that is loaded over the end of it at run time (the executable's own boot code, four overlays at
0x800B0548 and six mode packages at 0x800B8D58, all from TEKKEN3.BNS). Overlay variants share
addresses, so every row of functions/instructions/calls is keyed by (variant, addr).

The executable has no symbols. PsyQ links the game's objects first, then the startup code
(`__start`) and the Sony libraries, so every resident function below `__start` is game code and
is split into address-ordered work units of about UNIT_BYTES; library functions are classified by
the hardware they touch, the BIOS calls they make and the strings they print, and the remaining
ones inherit the library of their neighbours when both sides agree. Overlay code is game code,
split into units per variant the same way.

Re-running preserves the hand-edited columns (name, unit, status, owner, notes) of
sheets/functions.csv, so the sheet stays the source of truth across re-exports.
sheets/manual_names.csv (variant, addr, name, status, evidence, section, summary) always wins.

Sections (sheets/game_sections.csv): the game's screens / subsystems, one per game state of the
main loop, each with its entry functions. Every function gets the section that reaches it through
the call graph (`section` column; several sections -> `shared`, library code -> `psyq/<lib>`),
unless manual_names.csv says otherwise. The C is also projected per section into
src/sections/<section>.c, with the section's description and each function's summary on top.
"""
import csv
import hashlib
import os
import re
import shutil
import struct
import textwrap
from collections import Counter, defaultdict
from pathlib import Path

csv.field_size_limit(1 << 30)
OUT = Path(__file__).resolve().parent.parent                          # Tekken3Decomp/
WORK = Path(os.environ.get("T3_WORK", OUT.parent / "Tekken3"))         # Ghidra project, export/, extracted/
EXP, EX, SHEETS, SRC = WORK / "export", WORK / "extracted", OUT / "sheets", OUT / "src"
STATUSES = ["raw", "named", "typed", "clean", "verified"]
EXE = "TEKKEN3/SLUS_004.02"
UNIT_BYTES = 0x2000
RESIDENT = "resident"

# Evidence -> library, checked in order on each library function's decompiled C.
LIB_RULES = [
    ("libpress", [r"1f801820", r"1f801824", r"MDEC_", r"DecDCT"]),
    ("libcd", [r"1f80180[0-3]", r"CdRead", r"CDROM", r"Cd[A-Z][a-z]+", r"track overflow"]),
    ("libspu", [r"1f801c", r"1f801d", r"Spu[A-Z]", r"0xf0000009"]),
    ("libgpu", [r"1f801810", r"1f801814", r"SetGraph", r"DrawSync", r"LoadImage", r"GPU"]),
    ("libtap", [r"1f80104", r"Control TAP"]),
    ("libmcrd", [r"libmcrd", r"0xf4000001", r"0xf0000011", r"_card_", r"bu00", r"firstfile|nextfile"]),
    ("libetc", [r"VSync", r"intr timeout", r"unexpected interrupt", r"HookEntryInt", r"ChangeClearRCnt"]),
    ("libgte", [r"copFunction|setCopControlWord|getCopReg|setCopReg"]),
    ("libapi", [r"syscall\(", r"OpenEvent|EnableEvent|TestEvent|DeliverEvent|SysEnqIntRP"]),
]
BIOS_LIB = {"libc": {"abs", "setjmp", "strcat", "strncat", "strcmp", "strncmp", "strcpy", "strncpy",
                     "strlen", "strstr", "toupper", "memcpy", "memset", "rand", "srand", "malloc",
                     "free", "printf", "memchr", "InitHeap", "bzero", "puts", "exit", "_exit"}}


def clear_dir(d):
    """Empty a generated folder (files removed, folders kept: removing a folder fails on
    Windows while any program has it open)."""
    for f in sorted(d.rglob("*"), reverse=True):
        if f.is_file():
            f.unlink()
        else:
            try:
                f.rmdir()
            except OSError:
                pass


def read(p):
    """Rows of a CSV file as dicts."""
    with open(p, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def write(p, rows, cols):
    """Write rows (dicts) to a CSV file with the given column order."""
    with open(p, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, cols, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)


def classify(name, code, image):
    """PsyQ library of a resident library function, from its name (BIOS C functions) or the
    hardware registers / names its decompiled C mentions; "" if nothing matches."""
    for lib, names in BIOS_LIB.items():
        if name in names:
            return lib
    # Ghidra prints hardware register pointers kept in data as PTR_DAT_xxxxxxxx: add the
    # addresses they hold so the rules can see them.
    for m in re.finditer(r"PTR_[A-Za-z_]*?([0-9a-f]{8})\b", code):
        off = int(m.group(1), 16) - 0x80010000
        if 0 <= off <= len(image) - 4:
            v = struct.unpack_from("<I", image, off)[0]
            if 0x1F800000 <= v < 0x1F803000:
                code += f"\n// hw {v:08x}"
    for lib, pats in LIB_RULES:
        if any(re.search(p, code) for p in pats):
            return lib
    return ""


def assign_sections(rows, calls):
    """Fill each function's `section`: a hand-set one (manual_names.csv) wins; library code is
    `psyq/<lib>`; otherwise the game section(s) whose entry functions reach it through the static
    call graph (a variant's calls into resident code included): exactly one -> that section,
    several -> `shared`, none -> `unreached` (only called through pointers or the dispatcher)."""
    by_key = {(r["variant"], int(r["addr"], 16)): r for r in rows}
    edges = defaultdict(set)
    for c in calls:
        edges[(c["variant"], int(c["caller"], 16))].add(int(c["callee"], 16))
    reach = defaultdict(set)
    sections = read(SHEETS / "game_sections.csv")
    entry_of = {}
    for sec in sections:
        for e in sec["entries"].split(";"):
            v, a = e.split(":")
            entry_of[(v, int(a, 16))] = sec["section"]
    for sec in sections:
        todo = [k for k, s in entry_of.items() if s == sec["section"]]
        seen = set()
        while todo:
            k = todo.pop()
            if k in seen or k not in by_key:
                continue
            if entry_of.get(k, sec["section"]) != sec["section"]:
                continue  # another section's entry (main calls the resident state handlers)
            seen.add(k)
            reach[k].add(sec["section"])
            for callee in edges.get(k, ()):
                todo.append((k[0], callee) if (k[0], callee) in by_key else ("resident", callee))
    for k, r in by_key.items():
        if r["section"]:
            continue
        if r["module"] == "psyq":
            r["section"] = r["unit"]
        elif len(reach[k]) == 1:
            r["section"] = next(iter(reach[k]))
        else:
            r["section"] = "shared" if reach[k] else "unreached"


def project_sections(rows, variants):
    """src/sections/<section>.c: every function of a section with a header comment (name, code
    variant, address, summary), the section's description on top."""
    secs = {s["section"]: s for s in read(SHEETS / "game_sections.csv")}
    order = {v["variant"]: i for i, v in enumerate(variants)}
    by_sec = defaultdict(list)
    for r in rows:
        by_sec[r["section"]].append(r)
    out = SRC / "sections"
    if out.exists():
        clear_dir(out)
    out.mkdir(parents=True, exist_ok=True)
    rule = "*" * 98
    thin = "-" * 98
    for sec, rs in sorted(by_sec.items()):
        rs.sort(key=lambda r: (order[r["variant"]], int(r["addr"], 16)))
        info = secs.get(sec, {})
        title = info.get("title") or {"shared": "Code shared by several sections",
                                      "unreached": "Code only reached through pointers or overlays"}.get(sec, sec)
        named = sum(1 for r in rs if r["status"] != "raw")
        lines = ["/" + rule, f" * {title}", " *"]
        lines += [f" * {t}" for t in textwrap.wrap(info.get("description", ""), 94)]
        lines += [" *", f" * {len(rs)} functions, {named} named. GENERATED by tools/build_sheets.py from the",
                  " * sheets (Ghidra C): edit sheets/manual_*.csv, not this file.", " " + rule + "/", ""]
        for r in rs:
            lines += ["/" + thin,
                      f" * {r['name']}  ({r['variant']} {r['addr']}, {r['size']} bytes, status {r['status']})"]
            lines += [f" * {t}" for t in textwrap.wrap(r.get("summary", ""), 94)]
            lines += [" " + thin + "/", (OUT / r["c_path"]).read_text(encoding="utf-8")]
        (out / f"{sec.replace('/', '__')}.c").write_text("\n".join(lines) + "\n", encoding="utf-8")


def variant_rows():
    """Variants in a stable order: resident first, then overlays.csv order. With T3_PARTIAL=1,
    variants that have not been exported yet are left out (for trying the pipeline while Ghidra
    still works); otherwise a missing export is an error."""
    out = [{"variant": RESIDENT, "kind": "resident", "bns_index": "", "base": "0x80010000",
            "end": "0x800B0548", "sha1": "", "source": EXE}]
    for r in read(EX / "overlays.csv"):
        # memory.csv section `exe` is the boot image; a variant of that name would share its file.
        assert r["variant"] not in ("exe", RESIDENT), f"reserved variant name {r['variant']}"
        base, size = int(r["base"], 16), int(r["size"])
        kind = "init" if r["variant"] == "init" else ("overlay" if base == 0x800B0548 else "package")
        src = EXE if kind == "init" else f"TEKKEN3/TEKKEN3.BNS file {r['bns_index']}"
        if not (EXP / r["variant"] / "functions_raw.csv").exists():
            if os.environ.get("T3_PARTIAL") == "1":
                print(f"warning: {r['variant']} not exported yet, left out")
                continue
            raise SystemExit(f"{r['variant']}: no export in {EXP / r['variant']} (run tools/run_ghidra.sh)")
        out.append({"variant": r["variant"], "kind": kind, "bns_index": r["bns_index"] if kind != "init" else "",
                    "base": r["base"], "end": f"0x{base + size:08X}", "sha1": r["sha1"], "source": src})
    return out


def main():
    """Merge every variant's raw export into the sheets, keeping hand-edited columns, and project
    the C sources."""
    SHEETS.mkdir(parents=True, exist_ok=True)
    exe = (EX / "files" / EXE).read_bytes()
    pc0, gp0, t_addr, t_size = struct.unpack_from("<4I", exe, 0x10)
    image = exe[0x800:0x800 + t_size]
    variants = variant_rows()
    syms = {int(s["addr"], 16): s for s in read(EX / "symbols.csv")}
    start = next(a for a, s in syms.items() if s["name"] == "__start")
    prev = {}
    if (SHEETS / "functions.csv").exists():
        prev = {(r["variant"], r["addr"]): r for r in read(SHEETS / "functions.csv")}
    manual = {}
    if (SHEETS / "manual_names.csv").exists():
        manual = {(r["variant"], r["addr"].upper().replace("0X", "0x")): r for r in read(SHEETS / "manual_names.csv")}

    rows, calls, strings, globs, instr_n = [], [], [], [], Counter()
    raw_root = SRC / "raw_c"
    if raw_root.exists():
        clear_dir(raw_root)
    for v in variants:
        name = v["variant"]
        exp = EXP / name
        funcs = sorted(read(exp / "functions_raw.csv"), key=lambda r: int(r["addr"], 16))
        shutil.copytree(exp / "raw_c", raw_root / name, dirs_exist_ok=True)
        code = {f["addr"]: (exp / "raw_c" / f"{f['addr'][2:]}.c").read_text(encoding="utf-8") for f in funcs}
        libs = {}
        if name == RESIDENT:
            lib_addrs = [f["addr"] for f in funcs if int(f["addr"], 16) >= start]
            for f in funcs:
                if int(f["addr"], 16) >= start:
                    libs[f["addr"]] = classify(f["name"], code[f["addr"]], image)
            known = [(i, libs[a]) for i, a in enumerate(lib_addrs) if libs[a]]
            for i, a in enumerate(lib_addrs):
                if libs[a]:
                    continue
                before = [l for j, l in known if j < i]
                after = [l for j, l in known if j > i]
                p, n = (before[-1] if before else ""), (after[0] if after else "")
                libs[a] = p if p == n and p else "misc"
            libs[f"0x{start:08X}"] = "crt0"
        base = int(v["base"], 16)
        for f in funcs:
            a = int(f["addr"], 16)
            key = (name, f["addr"])
            old = prev.get(key, {})
            man = manual.get(key)
            if name == RESIDENT and a >= start:
                module, unit = "psyq", f"psyq/{libs[f['addr']]}"
                note = "library inferred from hardware/BIOS use or neighbours"
            else:
                module = "game"
                seg = (a - base) // UNIT_BYTES * UNIT_BYTES + base
                unit = f"game/seg_{seg:08X}" if name == RESIDENT else f"{name}/seg_{seg:08X}"
                note = ""
            fname = f["name"]
            status = "raw" if fname.startswith(("FUN_", "LAB_", "caseD_")) else "named"
            if name == RESIDENT and a in syms and int(syms[a]["size"] or 0) == 12:
                note = f"BIOS call stub: table {syms[a]['table']} function {syms[a]['number']}"
            summary = ""
            if man:
                fname, status, note = man["name"], man["status"], man["evidence"]
                summary = man.get("summary", "")
                old = {k: x for k, x in old.items() if k not in ("name", "status", "notes")}
            rows.append({
                **f, "variant": name,
                "name": old.get("name") or fname,
                "module": module,
                "unit": old.get("unit") or unit,
                "status": old.get("status") or status,
                "owner": old.get("owner", ""),
                "notes": old.get("notes") or note,
                "c_path": f"src/raw_c/{name}/{f['addr'][2:]}.c",
                "summary": summary,
                "section": (man or {}).get("section", ""),
            })
        calls += [{"variant": name, **r} for r in read(exp / "calls.csv")]
        strings += [{"variant": name, **r} for r in read(exp / "strings.csv")]
        globs += [{"variant": name, **r} for r in read(exp / "globals.csv")]

    assign_sections(rows, calls)
    fcols = ["variant", "addr", "name", "size", "module", "section", "unit", "status", "owner", "calls_out",
             "called_by", "decomp_lines", "decomp_ok", "signature", "summary", "c_path", "notes"]
    write(SHEETS / "functions.csv", rows, fcols)
    write(SHEETS / "calls.csv", calls, ["variant", "caller", "callee"])
    write(SHEETS / "strings.csv", strings, ["variant", "addr", "section", "len", "text", "ref_funcs"])
    write(SHEETS / "globals.csv", globs, ["variant", "addr", "name", "section", "datatype", "size", "xrefs"])

    # instructions.csv: all variants, keyed by (variant, addr).
    with open(SHEETS / "instructions.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["variant", "addr", "func", "bytes", "asm", "delay", "pcode"])
        for v in variants:
            with open(EXP / v["variant"] / "instructions.csv", newline="", encoding="utf-8") as src:
                r = csv.reader(src)
                next(r)
                for row in r:
                    w.writerow([v["variant"], *row])
                    instr_n[v["variant"]] += 1

    # memory.csv: the executable image as the BIOS loads it (section `exe`, 0x80010000..) and
    # every variant's own bytes (section = variant), 64 bytes per row.
    with open(SHEETS / "memory.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["addr", "section", "hex"])
        blobs = [("exe", t_addr, image)]
        for v in variants[1:]:
            blobs.append((v["variant"], int(v["base"], 16), (EX / "overlays" / f"{v['variant']}.bin").read_bytes()))
        for sec, base, data in blobs:
            for o in range(0, len(data), 64):
                w.writerow([f"0x{base + o:08X}", sec, data[o:o + 64].hex().upper()])

    for name in ["sections.csv", "registers.csv"]:
        shutil.copy(EXP / RESIDENT / name, SHEETS / name)
    for name in ["symbols.csv", "disc_files.csv", "bns_toc.csv"]:
        shutil.copy(EX / name, SHEETS / name)

    nf = Counter(r["variant"] for r in rows)
    for v in variants:
        v["functions"] = nf[v["variant"]]
        v["instructions"] = instr_n[v["variant"]]
    write(SHEETS / "variants.csv", variants,
          ["variant", "kind", "bns_index", "base", "end", "sha1", "source", "functions", "instructions"])

    by_unit = defaultdict(list)
    for r in rows:
        by_unit[(r["variant"], r["unit"])].append(r)
    units = []
    for (vname, u), rs in by_unit.items():
        st = Counter(r["status"] for r in rs)
        units.append({
            "unit": u, "variant": vname, "module": rs[0]["module"],
            "library": u.split("/")[1] if u.startswith("psyq/") else "",
            "first_addr": rs[0]["addr"], "last_addr": rs[-1]["addr"],
            "n_funcs": len(rs), "total_size": sum(int(r["size"]) for r in rs),
            **{s: st.get(s, 0) for s in STATUSES},
            "owner": "", "src_path": f"src/units/{u.replace('/', '__')}.c",
        })
    order = {v["variant"]: i for i, v in enumerate(variants)}
    units.sort(key=lambda r: (order[r["variant"]], r["module"] != "game", int(r["first_addr"], 16)))
    write(SHEETS / "units.csv", units, ["unit", "variant", "module", "library", "first_addr", "last_addr",
                                        "n_funcs", "total_size", *STATUSES, "owner", "src_path"])

    # Projection: each unit's functions concatenated into one C file.
    units_dir = SRC / "units"
    if units_dir.exists():
        clear_dir(units_dir)
    units_dir.mkdir(parents=True, exist_ok=True)
    for (vname, u), rs in by_unit.items():
        with open(units_dir / f"{u.replace('/', '__')}.c", "a", encoding="utf-8") as fh:
            fh.write(f"// unit {u} ({vname}, {rs[0]['module']}): {len(rs)} functions {rs[0]['addr']}..{rs[-1]['addr']}\n"
                     f"// GENERATED from sheets/functions.csv - edit the sheet, not this file.\n\n")
            for r in rs:
                fh.write((OUT / r["c_path"]).read_text(encoding="utf-8"))
                fh.write("\n")

    project_sections(rows, variants)

    cnf = (EX / "files" / "SYSTEM.CNF").read_text(errors="replace")
    sp0 = struct.unpack_from("<I", exe, 0x30)[0]
    meta = [
        ("game_id", "SLUS-00402"),
        ("title", "Tekken 3 (USA)"),
        ("platform", "Sony PlayStation (MIPS R3000A, little endian)"),
        ("engine", "Namco game code + PsyQ libraries (libapi, libc, libetc, libgpu, libgte, libcd, libspu, "
                   "libpress, libmcrd, libtap)"),
        ("exe", EXE),
        ("entry_point", f"0x{pc0:08X}"),
        ("gp", "0x8009B9A8"),
        ("text", f"0x{t_addr:08X}+0x{t_size:X}"),
        ("resident_end", "0x800B0548"),
        ("bss", "0x8009B9A8..0x800B0548 (cleared by __start)"),
        ("overlay_base", "0x800B0548 (overlays, BNS files 5..8; the executable's own init code)"),
        ("package_base", "0x800B8D58 (mode packages, BNS files 0, 9, 10, 11, 301, 302; start of the heap)"),
        ("bns_toc", "0x80024400 (303 entries: sector offset, byte size)"),
        ("stack", f"0x{sp0:08X}"),
        ("system_cnf", " ".join(cnf.split())),
        ("exe_sha1", hashlib.sha1(exe).hexdigest()),
        ("exe_size", str(len(exe))),
        ("symbols", "none shipped; BIOS call stubs named by tools/find_stubs.py"),
        ("toolchain", "Ghidra 12.1.4 (ELF wrappers from tools/psx2elf.py + tools/bns_overlays.py, "
                      "MIPS:LE:32:default) via ghidra-cli"),
    ]
    write(SHEETS / "meta.csv", [{"key": k, "value": v} for k, v in meta], ["key", "value"])

    tot = Counter(r["status"] for r in rows)
    lib = Counter(r["unit"] for r in rows if r["module"] == "psyq")
    print(f"{len(rows)} functions in {len(variants)} variants, {sum(instr_n.values())} instructions, "
          f"{len(units)} units, status {dict(tot)}")
    print("per variant:", {v["variant"]: (v["functions"], v["instructions"]) for v in variants})
    print("libraries:", dict(lib))


if __name__ == "__main__":
    main()
