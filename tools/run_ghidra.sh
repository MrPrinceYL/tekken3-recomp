#!/usr/bin/env bash
# Import, analyze and export every code variant of Tekken 3 with ghidra-cli.
#
#   resident   the executable up to 0x800B0548 (extracted/resident.elf)
#   <variant>  each row of extracted/overlays.csv: the resident executable plus one overlay or
#              mode package at its load address (extracted/overlays/<variant>.elf); only the
#              variant's own range is exported from it
#
# Usage: bash run_ghidra.sh [variant ...]   (default: resident and every variant)
# Env:   T3_WORK   work folder (default ../../Tekken3: extracted/, ghidra/, export/)
#        GHIDRA    ghidra-cli executable
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd -W 2>/dev/null || pwd)"
WORK="${T3_WORK:-$(cd "$HERE/../.." && pwd -W 2>/dev/null || pwd)/Tekken3}"
GHIDRA="${GHIDRA:-ghidra}"
GP=0x8009B9A8
export GHIDRA_CLI_READ_TIMEOUT=0
mkdir -p "$WORK/ghidra" "$WORK/export"

g() {  # ghidra-cli, retried: a freshly (re)started bridge sometimes refuses the first connection
  local n
  for n in 1 2 3; do
    "$GHIDRA" --projects-dir "$WORK/ghidra" --project TEKKEN3 "$@" && return 0
    echo "retrying ($n): $*" >&2
    sleep 10
  done
  return 1
}

bridge_pid() {
  cat "$LOCALAPPDATA"/ghidra-cli/bridge-*.pid 2>/dev/null | head -1 | tr -d '

 '
}

bridge_stop() {  # graceful: the bridge commits and saves its program only when it shuts down
  "$GHIDRA" --projects-dir "$WORK/ghidra" --project TEKKEN3 stop >/dev/null 2>&1 || true
}

bridge_stop_empty() {  # a bridge started without a program does not exit after `stop`;
                       # it holds nothing unsaved, so end its JVM (found by its command line:
                       # `-process` directly followed by `-noanalysis`, i.e. no program)
  timeout 60 "$GHIDRA" --projects-dir "$WORK/ghidra" --project TEKKEN3 stop >/dev/null 2>&1 || true
  sleep 5
  powershell -NoProfile -Command "Get-CimInstance Win32_Process -Filter \"Name='java.exe'\" | Where-Object { \$_.CommandLine -match '\"-process\" \"-noanalysis\"' } | ForEach-Object { Stop-Process -Id \$_.ProcessId -Force }" || true
  sleep 2
  rm -f "$LOCALAPPDATA"/ghidra-cli/bridge-*.pid "$LOCALAPPDATA"/ghidra-cli/bridge-*.port
}

has_program() {  # programs imported by this script are marked; see process()
  [ -f "$WORK/ghidra/$1.imported" ]
}

process() {  # name elf range_lo range_hi gap_lo gap_hi clean
  local name=$1 elf=$2 lo=$3 hi=$4 glo=$5 ghi=$6 clean=$7 prog done n f
  prog="$(basename "$elf")"
  done="$WORK/ghidra/$prog.analyzed"
  echo "=== $name ($prog) $lo..$hi"
  # One program per bridge session (a bridge session is one Ghidra transaction; ghidra-cli's
  # `analyze` also fails in a session that already worked on another program).
  bridge_stop
  if [ ! -f "$done" ]; then
    if ! has_program "$prog"; then
      if [ -f "$WORK/ghidra/TEKKEN3.gpr" ]; then
        # Start the bridge explicitly first: a bridge started implicitly by a command keeps
        # that command's output open, so a client whose output is piped never seems to return.
        g start >/dev/null 2>&1 </dev/null
        g import "$elf" --no-analyze </dev/null
      else
        # The first import creates the project (`project create` ignores --projects-dir). Its
        # client starts the bridge itself and may not return: wait for the project, then end it.
        "$GHIDRA" --projects-dir "$WORK/ghidra" --project TEKKEN3 import "$elf" --no-analyze </dev/null >/dev/null 2>&1 &
        local imp=$! i
        for i in $(seq 1 300); do
          [ -d "$WORK/ghidra/TEKKEN3.rep" ] && "$GHIDRA" --projects-dir "$WORK/ghidra" --project TEKKEN3             program list </dev/null 2>/dev/null | grep -q "$prog" && break
          sleep 2
        done
        kill "$imp" 2>/dev/null || true
      fi
      bridge_stop_empty
      touch "$WORK/ghidra/$prog.imported"
    fi
    g --program "$prog" script run "$HERE/SetGp.java" -- "$GP"
    g --program "$prog" script run "$HERE/ApplySymbols.java" -- "$WORK/extracted/symbols.csv"
    g --program "$prog" script run "$HERE/Analyze.java"
    g --program "$prog" script run "$HERE/FixNoReturn.java"
    if [ "$name" = resident ]; then
      g --program "$prog" script run "$HERE/CreateFunctions.java" -- "$WORK/extracted/resident_seeds.csv"
    fi
    g --program "$prog" script run "$HERE/CreateGapFunctions.java" -- "$glo" "$ghi"
    if [ "$clean" = 1 ]; then
      g --program "$prog" script run "$HERE/CleanFunctions.java" -- "$lo" "$hi"
    fi
    bridge_stop  # saves the analysis
    touch "$done"
  fi
  if [ ! -f "$WORK/ghidra/$prog.delayfix" ]; then
    g --program "$prog" script run "$HERE/FixDelaySlotTargets.java"
    bridge_stop  # saves
    touch "$WORK/ghidra/$prog.delayfix"
  fi
  if [ ! -f "$WORK/ghidra/$prog.ptrcode" ]; then
    g --program "$prog" script run "$HERE/DisassemblePointerTargets.java" -- "$glo" "$ghi"
    bridge_stop  # saves
    touch "$WORK/ghidra/$prog.ptrcode"
  fi
  if [ ! -f "$WORK/ghidra/$prog.seeds" ]; then
    # Functions only reachable from other code variants: a variant's functions that only the
    # resident code calls (stubs such as `jr ra; li v0,n`), resident functions only overlays call.
    local seeds="$WORK/extracted/overlays/${name}_seeds.csv"
    [ "$name" = resident ] && seeds="$WORK/extracted/resident_seeds.csv"
    g --program "$prog" script run "$HERE/CreateFunctions.java" -- "$seeds"
    bridge_stop  # saves
    touch "$WORK/ghidra/$prog.seeds"
  fi
  # Names, variable names and comments from the sheets (names and comments only: the code and
  # its p-code are unchanged). Runs before every export so sheet edits always reach the C.
  g --program "$prog" script run "$HERE/ApplyAnnotations.java" -- "$HERE/../sheets" "$name"
  bridge_stop  # saves
  rm -rf "$WORK/export/$name"
  g --program "$prog" script run "$HERE/ExportPcode.java" -- "$WORK/export/$name" "$lo" "$hi"
  g --program "$prog" script run "$HERE/ExportSheets.java" -- "$WORK/export/$name" "$lo" "$hi"
  bridge_stop
  n=$(( $(wc -l < "$WORK/export/$name/instructions.csv") - 1 ))
  if [ "$n" -le 0 ]; then
    echo "$name: export has no instructions (analysis not saved?); delete $done and rerun" >&2
    exit 1
  fi
  f=$(( $(wc -l < "$WORK/export/$name/functions_raw.csv") - 1 ))
  if [ "$f" -le 0 ]; then
    echo "$name: export has no functions; delete $done and rerun" >&2
    exit 1
  fi
  echo "$name: $n instructions, $f functions exported"
}

want() { [ $# -eq 0 ] && return 0; local v; for v in "${SEL[@]}"; do [ "$v" = "$1" ] && return 0; done; return 1; }
SEL=("$@")

if [ ${#SEL[@]} -eq 0 ] || want resident; then
  process resident "$WORK/extracted/resident.elf" 0x80010000 0x800B0548 0x80028000 0x800B0548 0
fi
tail -n +2 "$WORK/extracted/overlays.csv" | tr -d '\r' | while IFS=, read -r variant idx base size sha elf; do
  if [ ${#SEL[@]} -gt 0 ] && ! want "$variant"; then continue; fi
  hi=$(printf '0x%08X' $((base + size)))
  process "$variant" "$WORK/extracted/$elf" "$base" "$hi" "$base" "$hi" 1
done
echo "done"
