// Create functions for code Ghidra's auto-analysis skipped (typically callbacks and state
// handlers that are only reached through pointers). Tekken 3's code ranges hold data tables too,
// so a gap address only becomes a function when there is evidence it is code:
//   - it is a stack-frame prologue (addiu sp,sp,-N), or
//   - its address is stored as a 32-bit word somewhere in the program image (a function pointer)
// and the result decodes cleanly and ends in a jump/return (CleanFunctions' rule).
// Repeats until nothing new is found.
// Usage: ghidra script run CreateGapFunctions.java -- <start hex> <end hex>
//@category Analysis
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;

import java.util.*;

public class CreateGapFunctions extends GhidraScript {
    private boolean sane(Function f) throws Exception {
        Listing listing = currentProgram.getListing();
        boolean ends = false;
        long n = 0;
        for (Instruction ins : listing.getInstructions(f.getBody(), true)) {
            n++;
            String m = ins.getMnemonicString();
            if (m.equals("jr") || m.equals("j") || m.equals("_jr") || m.equals("_j")) ends = true;
        }
        return ends && n > 0 && n * 4 >= f.getBody().getNumAddresses();
    }

    @Override
    protected void run() throws Exception {
        Memory mem = currentProgram.getMemory();
        FunctionManager fm = currentProgram.getFunctionManager();
        Listing listing = currentProgram.getListing();
        AddressSpace sp = currentProgram.getAddressFactory().getDefaultAddressSpace();
        long lo = Long.parseLong(getScriptArgs()[0].replace("0x", ""), 16);
        long hi = Long.parseLong(getScriptArgs()[1].replace("0x", ""), 16);

        // Every aligned word of the initialized image that points into the range.
        Set<Long> ptrs = new HashSet<>();
        for (MemoryBlock b : mem.getBlocks()) {
            if (!b.isInitialized()) continue;
            byte[] buf = new byte[(int) b.getSize()];
            b.getBytes(b.getStart(), buf);
            long base = b.getStart().getOffset();
            for (int i = 0; i + 4 <= buf.length; i += 4) {
                long v = (buf[i] & 0xFFL) | (buf[i + 1] & 0xFFL) << 8 | (buf[i + 2] & 0xFFL) << 16 | (buf[i + 3] & 0xFFL) << 24;
                if (v >= lo && v < hi && (v & 3) == 0) ptrs.add(v);
            }
        }
        int created = 0, rejected = 0, pass = 0;
        boolean changed = true;
        while (changed && pass < 8) {
            changed = false;
            pass++;
            Address a = sp.getAddress(lo);
            Address end = sp.getAddress(hi);
            while (a.compareTo(end) < 0 && !monitor.isCancelled()) {
                Function f = fm.getFunctionContaining(a);
                if (f != null) {
                    Address next = f.getBody().getMaxAddress().add(1);
                    a = next.compareTo(a) > 0 ? next : a.add(4);
                    continue;
                }
                int w = mem.getInt(a);
                boolean prologue = (w >>> 16) == 0x27BD && (w & 0x8000) != 0;
                if (w == 0 || !(prologue || ptrs.contains(a.getOffset()))) {
                    a = a.add(4);
                    continue;
                }
                AddressSetView fresh = new AddressSet();
                if (listing.getInstructionAt(a) == null) {
                    if (listing.getDefinedDataAt(a) != null) listing.clearCodeUnits(a, a, false);
                    DisassembleCommand dis = new DisassembleCommand(a, null, true);
                    dis.applyTo(currentProgram, monitor);
                    fresh = dis.getDisassembledAddressSet();
                }
                if (listing.getInstructionAt(a) != null && new CreateFunctionCmd(a).applyTo(currentProgram, monitor)) {
                    Function nf = fm.getFunctionAt(a);
                    if (nf != null && sane(nf)) {
                        created++;
                        changed = true;
                        a = nf.getBody().getMaxAddress().add(1);
                        continue;
                    }
                    if (nf != null) fm.removeFunction(a);
                    rejected++;
                }
                // Not code after all: undo what this attempt disassembled.
                for (AddressRange r : fresh) listing.clearCodeUnits(r.getMinAddress(), r.getMaxAddress(), false, monitor);
                a = a.add(4);
            }
            println("pass " + pass + ": " + created + " functions created, " + rejected + " rejected");
        }
        println("done: created " + created + " functions, total " + fm.getFunctionCount());
    }
}
