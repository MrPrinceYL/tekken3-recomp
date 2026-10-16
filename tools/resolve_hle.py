"""NOT PART OF THE TEKKEN 3 PIPELINE - do not run it. Inherited from the Risk decomp: it does
not know hle.csv's `variant` column and would blank the addresses of hooks whose function has no
unique name (the MDEC sync hooks in pkg010 / pkg301). Tekken 3 keeps hle.csv addresses by hand.

Fill sheets/hle.csv addresses from sheets/functions.csv by function name.

hle.csv lists library functions the Rust runtime replaces (psx-runtime/src/kernel.rs `hle` dispatches on the
name). The addresses are per-game, so after naming (sheets/manual_names.csv) this resolves each name
to its address here. Rows whose name is not found are kept with an empty address (gen_rust.py
skips them) and reported.
"""
import csv
from pathlib import Path

SHEETS = Path(__file__).resolve().parent.parent / "sheets"


def main():
    with open(SHEETS / "functions.csv", newline="", encoding="utf-8") as fh:
        by_name = {}
        for r in csv.DictReader(fh):
            by_name.setdefault(r["name"], []).append(r["addr"])
    with open(SHEETS / "hle.csv", newline="", encoding="utf-8") as fh:
        rd = csv.DictReader(fh)
        cols, rows = rd.fieldnames, list(rd)
    missing = []
    for r in rows:
        addrs = by_name.get(r["name"], [])
        if len(addrs) == 1:
            r["addr"] = "0x" + addrs[0][2:].upper()
        else:
            r["addr"] = ""
            missing.append(f"{r['name']} ({len(addrs)} matches)")
    with open(SHEETS / "hle.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, cols)
        w.writeheader()
        w.writerows(rows)
    print(f"{len(rows) - len(missing)}/{len(rows)} HLE functions resolved")
    for m in missing:
        print("  unresolved:", m)


if __name__ == "__main__":
    main()
