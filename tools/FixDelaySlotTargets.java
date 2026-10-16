// Disassemble the code after delay slots that are also branch targets.
// PsyQ code branches straight into another branch's delay slot (e.g. libgte's square root:
// `bltz t3,L` ... `b M` / `L: li t3,0x18` (delay slot) / `srav ...`). Ghidra keeps L only as
// the delay slot, so the instructions after it, which run only when L is entered by the other
// branch, are never disassembled. Disassemble them and add them to the containing function.
// Usage: ghidra script run CreateGapFunctions.java ... ; ghidra script run FixDelaySlotTargets.java
//@category Analysis
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

import java.util.*;

public class FixDelaySlotTargets extends GhidraScript {
    @Override
    protected void run() throws Exception {
        Listing listing = currentProgram.getListing();
        FunctionManager fm = currentProgram.getFunctionManager();
        ReferenceManager refs = currentProgram.getReferenceManager();
        Set<Function> touched = new HashSet<>();
        int fixed = 0;
        for (Instruction ins : listing.getInstructions(true)) {
            if (monitor.isCancelled()) break;
            if (!ins.isInDelaySlot()) continue;
            boolean target = false;
            for (Reference r : refs.getReferencesTo(ins.getAddress())) {
                if (r.getReferenceType().isFlow() && !r.getReferenceType().isFallthrough()) {
                    // A branch into the slot from anywhere but its own branch instruction.
                    Instruction from = listing.getInstructionAt(r.getFromAddress());
                    if (from == null || !from.getMaxAddress().add(1).equals(ins.getAddress())) target = true;
                }
            }
            if (!target) continue;
            Address next = ins.getMaxAddress().add(1);
            if (listing.getInstructionAt(next) != null || listing.getDefinedDataAt(next) != null) continue;
            DisassembleCommand dis = new DisassembleCommand(next, null, true);
            dis.applyTo(currentProgram, monitor);
            if (dis.getDisassembledAddressSet().isEmpty()) continue;
            fixed++;
            println("delay slot " + ins.getAddress() + " is a branch target: disassembled from " + next);
            Function f = fm.getFunctionContaining(ins.getAddress());
            if (f != null) touched.add(f);
        }
        for (Function f : touched) {
            // The new code is reached only through the delay slot: add it to the function body.
            AddressSet body = new AddressSet(f.getBody());
            for (Instruction ins : listing.getInstructions(f.getBody(), true)) {
                if (!ins.isInDelaySlot()) continue;
                Address a = ins.getMaxAddress().add(1);
                while (listing.getInstructionAt(a) != null && fm.getFunctionContaining(a) == null) {
                    Instruction n = listing.getInstructionAt(a);
                    body.add(n.getMinAddress(), n.getMaxAddress());
                    if (!n.getFlowType().isFallthrough() && !n.hasFallthrough()) {
                        // include its delay slot, then stop
                        Instruction ds = n.getNext();
                        if (ds != null && ds.isInDelaySlot()) body.add(ds.getMinAddress(), ds.getMaxAddress());
                        break;
                    }
                    a = n.getMaxAddress().add(1);
                }
            }
            f.setBody(body);
        }
        println("done: " + fixed + " delay-slot targets, " + touched.size() + " functions extended");
    }
}
