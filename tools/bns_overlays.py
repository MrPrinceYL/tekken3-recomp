"""Find the code overlays inside TEKKEN3.BNS and build one Ghidra input per code variant.

Usage: python bns_overlays.py <extracted_dir>

TEKKEN3.BNS is an archive of 303 files. Its table of contents is compiled into the executable at
0x80024400: one (sector offset, byte size) pair per file, read by the BNS loader (0x8006BF20,
which adds the sector offset to the BNS file's LBA from CdSearchFile). Some files are code linked
to a fixed address and loaded over the end of the executable image:

  0x800B0548  small overlays (the executable ships its boot/init code there; files 5..8 replace it)
  0x800B8D58  mode packages: code and data loaded at the start of the game's heap (files 0, 9..11,
              301, 302)

A file is code if it holds `jr ra` instructions; its load address is the one for which its
`jal` targets land on function prologues (`addiu sp,sp,-N`) inside the file. Both are checked here,
so a new candidate address or a misdetected file stops the build instead of producing a wrong
image.

Writes (into <extracted_dir>):
  resident.elf        the executable up to 0x800B0548 (its resident code and data) for Ghidra
  resident_seeds.csv  resident functions that only overlay code calls (seeds for Ghidra)
  bns_toc.csv         index, sector, offset, size, is_code, load_addr
  overlays.csv        variant, bns_index, base, size, sha1, elf
  overlays/<variant>_seeds.csv  resident calls into the variant that start functions there
  overlays/<variant>.bin and <variant>.elf  (resident executable + the variant at its base);
                      variant `init` is the executable's own init code at 0x800B0548
"""
import csv
import hashlib
import os
import struct
import sys
from collections import Counter

TOC_ADDR = 0x80024400
TOC_COUNT = 303
EXE = "TEKKEN3/SLUS_004.02"
BNS = "TEKKEN3/TEKKEN3.BNS"
BASES = (0x800B0548, 0x800B8D58)
RAM_END = 0x80200000


def words(data):
    """All little-endian 32-bit words of `data`."""
    return struct.unpack_from("<%dI" % (len(data) // 4), data)


def load_base(data):
    """The fixed address this code file is linked for (one of BASES), or None if it isn't code."""
    w = words(data)
    if sum(1 for x in w if x == 0x03E00008) < 3:
        return None
    pro = {4 * i for i, x in enumerate(w) if (x >> 16) == 0x27BD and x & 0x8000}
    votes = Counter()
    for x in w:
        if x >> 26 != 3:
            continue
        t = ((x & 0x3FFFFFF) << 2) | 0x80000000
        for b in BASES:
            if t - b in pro:
                votes[b] += 1
    if not votes:
        return None
    (best, n), = votes.most_common(1)
    assert n >= 5 and all(c * 3 < n for b, c in votes.items() if b != best), (votes, "ambiguous base")
    return best


RESIDENT_END = 0x800B0548  # the executable's resident part ends where the overlays begin
EXE_INIT_END = 0x800B0CF0  # the executable's own overlay-area contents: its boot/init code
CODE_START, CODE_END = 0x80028000, 0x80095300  # resident code (game code, crt0, libraries)


def plausible_start(data, off):
    """True if `data[off]` looks like the first instruction of a function: a stack-frame prologue,
    a `jr ra` (a stub such as `jr ra; li v0,size`), or the first non-zero word after a `jr ra` +
    delay slot (leaf functions)."""
    if off < 0 or off + 4 > len(data):
        return False
    w = struct.unpack_from("<I", data, off)[0]
    if w == 0:
        return False
    if (w >> 16) == 0x27BD and w & 0x8000 or off == 0 or w == 0x03E00008:
        return True  # prologue, start of the file, or a stub that only returns (`jr ra`)
    p = off - 4
    while p >= 0 and struct.unpack_from("<I", data, p)[0] == 0:
        p -= 4
    if p < 0:
        return False
    # The last non-zero word is either the `jr ra` itself (its delay slot was a nop, skipped
    # with the padding) or the delay slot right after it.
    return (struct.unpack_from("<I", data, p)[0] == 0x03E00008
            or p >= 4 and struct.unpack_from("<I", data, p - 4)[0] == 0x03E00008)


def variant_elf(resident, pc0, base, data):
    """ELF of the resident executable plus one code variant at `base`. Resident `jal`s into the
    variant's range stay only if their target is a plausible function start in this variant:
    the resident code calls fixed addresses that belong to whichever overlay is loaded, and a
    call meant for another overlay would make Ghidra start a function in the middle of this one."""
    res = bytearray(resident)
    dropped = 0
    for i in range(0, len(res), 4):
        w = struct.unpack_from("<I", res, i)[0]
        if w >> 26 != 3:
            continue
        t = ((w & 0x3FFFFFF) << 2) | 0x80000000
        if base <= t < base + len(data) and not plausible_start(data, t - base):
            struct.pack_into("<I", res, i, 0)
            dropped += 1
    import psx2elf  # noqa: E402  (same folder)
    return psx2elf.build_segments(pc0, [(".text", 0x80010000, bytes(res)), (".ovl", base, data)]), dropped


def main():
    """Read the BNS table of contents, classify every file and write the variant ELFs, the
    overlay images, resident_seeds.csv, bns_toc.csv and overlays.csv."""
    ex = sys.argv[1]
    exe = open(os.path.join(ex, "files", EXE), "rb").read()
    bns = open(os.path.join(ex, "files", BNS), "rb").read()
    t_addr = struct.unpack_from("<I", exe, 0x18)[0]
    toc = [struct.unpack_from("<iI", exe, 0x800 + TOC_ADDR - t_addr + 8 * i) for i in range(TOC_COUNT)]
    end = toc[-1][0] * 0x800 + toc[-1][1]
    assert end <= len(bns) < end + 0x800, "BNS table of contents does not match the file"
    out = os.path.join(ex, "overlays")
    os.makedirs(out, exist_ok=True)
    pc0 = struct.unpack_from("<I", exe, 0x10)[0]
    resident = exe[0x800:0x800 + RESIDENT_END - t_addr]
    import psx2elf  # noqa: E402  (same folder)
    open(os.path.join(ex, "resident.elf"), "wb").write(psx2elf.build_segments(pc0, [(".text", t_addr, resident)]))
    variants = [("init", -1, RESIDENT_END, exe[0x800 + RESIDENT_END - t_addr:0x800 + EXE_INIT_END - t_addr])]
    rows = []
    for i, (sec, size) in enumerate(toc):
        data = bns[sec * 0x800:sec * 0x800 + size]
        base = load_base(data) if size else None
        rows.append({"index": i, "sector": sec, "offset": f"0x{sec * 0x800:X}", "size": size,
                     "is_code": int(base is not None), "load_addr": f"0x{base:08X}" if base else ""})
        if base is not None:
            assert base + size <= RAM_END
            variants.append((f"{'ovl' if base == BASES[0] else 'pkg'}{i:03d}", i, base, data))
    ovl = []
    for name, i, base, data in variants:
        open(os.path.join(out, name + ".bin"), "wb").write(data)
        blob, dropped = variant_elf(resident, pc0, base, data)
        open(os.path.join(out, name + ".elf"), "wb").write(blob)
        ovl.append({"variant": name, "bns_index": i, "base": f"0x{base:08X}", "size": len(data),
                    "sha1": hashlib.sha1(data).hexdigest(), "elf": f"overlays/{name}.elf"})
        # Resident calls into this variant that are plausible function starts: seeds for Ghidra
        # (a stub only the resident code calls is otherwise never disassembled).
        targets = set()
        for o in range(0, len(resident) - 3, 4):
            w = struct.unpack_from("<I", resident, o)[0]
            t = ((w & 0x3FFFFFF) << 2) | 0x80000000
            if w >> 26 == 3 and base <= t < base + len(data) and plausible_start(data, t - base):
                targets.add(t)
        with open(os.path.join(out, name + "_seeds.csv"), "w", newline="") as fh:
            fh.write("addr" + chr(10) + "".join(f"0x{t:08X}" + chr(10) for t in sorted(targets)))
        print(f"{name}: BNS file {i} -> {base:#010x}..{base + len(data):#010x} "
              f"({dropped} resident calls into it dropped for analysis)")
    # Resident functions that only overlay code calls (or points to): the resident program alone never sees
    # those calls, so Ghidra would not create them. Seed them for its analysis.
    seeds = {}
    for name, i, base, data in variants:
        for o in range(0, len(data) - 3, 4):
            w = struct.unpack_from("<I", data, o)[0]
            if w >> 26 in (2, 3):  # j / jal
                t = ((w & 0x3FFFFFF) << 2) | 0x80000000
            elif w & 3 == 0:  # a function pointer in the overlay's data (callback tables)
                t = w
            else:
                continue
            if CODE_START <= t < CODE_END and plausible_start(resident, t - t_addr):
                seeds.setdefault(t, set()).add(name)
    with open(os.path.join(ex, "resident_seeds.csv"), "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["addr", "called_from"])
        for t in sorted(seeds):
            w.writerow([f"0x{t:08X}", ";".join(sorted(seeds[t]))])
    print(f"{len(seeds)} resident functions called from overlay code -> resident_seeds.csv")
    with open(os.path.join(ex, "bns_toc.csv"), "w", newline="") as fh:
        w = csv.DictWriter(fh, list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    with open(os.path.join(ex, "overlays.csv"), "w", newline="") as fh:
        w = csv.DictWriter(fh, list(ovl[0]))
        w.writeheader()
        w.writerows(ovl)


if __name__ == "__main__":
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    main()
