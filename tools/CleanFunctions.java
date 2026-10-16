// Remove functions (and their instructions) that auto-analysis created on data in [start, end).
// Tekken 3's resident code calls overlay functions at fixed addresses; in a program whose image
// holds other bytes there (the executable's own data, another overlay), those calls make Ghidra
// "disassemble" zeros or data. A function is kept only if its entry decodes to a real
// instruction (not a zero word), it holds no undecodable bytes and it ends in a return or jump.
// Then every instruction in the range that is no longer inside a function is cleared too.
// Usage: ghidra script run CleanFunctions.java -- <start hex> <end hex>
//@category Analysis
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;

import java.util.*;

public class CleanFunctions extends GhidraScript {
    @Override
    protected void run() throws Exception {
        AddressSpace sp = currentProgram.getAddressFactory().getDefaultAddressSpace();
        Address lo = sp.getAddress(Long.parseLong(getScriptArgs()[0].replace("0x", ""), 16));
        Address hi = sp.getAddress(Long.parseLong(getScriptArgs()[1].replace("0x", ""), 16) - 1);
        AddressSet range = new AddressSet(lo, hi);
        Memory mem = currentProgram.getMemory();
        Listing listing = currentProgram.getListing();
        FunctionManager fm = currentProgram.getFunctionManager();
        List<Function> bad = new ArrayList<>();
        for (Function f : fm.getFunctions(range, true)) {
            Address ep = f.getEntryPoint();
            boolean ok = mem.getInt(ep) != 0;
            boolean ends = false;
            long n = 0;
            for (Instruction ins : listing.getInstructions(f.getBody(), true)) {
                n++;
                String m = ins.getMnemonicString();
                if (m.equals("jr") || m.equals("j") || m.equals("_jr") || m.equals("_j")) ends = true;
            }
            if (n == 0 || n * 4 < f.getBody().getNumAddresses()) ok = false; // undecodable bytes
            if (!ends) ok = false;
            if (!ok) bad.add(f);
        }
        for (Function f : bad) fm.removeFunction(f.getEntryPoint());
        // Clear instructions in the range that no function owns any more.
        AddressSet orphan = new AddressSet();
        for (Instruction ins : listing.getInstructions(range, true)) {
            if (fm.getFunctionContaining(ins.getAddress()) == null)
                orphan.add(ins.getMinAddress(), ins.getMaxAddress());
        }
        for (AddressRange r : orphan) listing.clearCodeUnits(r.getMinAddress(), r.getMaxAddress(), false, monitor);
        int kept = 0;
        for (Function f : fm.getFunctions(range, true)) kept++;
        println("removed " + bad.size() + " functions, " + orphan.getNumAddresses()
            + " bytes of orphan instructions; kept " + kept + " functions in range");
    }
}
