// Give the MIPS gp register its value (set once by __start: lui gp,0x800A; addiu gp,gp,0x2C80)
// over the whole executable, so auto-analysis resolves gp-relative (small data) references.
// Usage: ghidra script run SetGp.java -- <gp hex>
//@category Analysis
import ghidra.app.script.GhidraScript;
import ghidra.program.model.lang.Register;
import ghidra.program.model.mem.MemoryBlock;

import java.math.BigInteger;

public class SetGp extends GhidraScript {
    @Override
    protected void run() throws Exception {
        long gp = Long.parseLong(getScriptArgs()[0].replace("0x", ""), 16);
        Register r = currentProgram.getRegister("gp");
        for (MemoryBlock b : currentProgram.getMemory().getBlocks()) {
            if (!b.isExecute()) continue;
            currentProgram.getProgramContext().setValue(r, b.getStart(), b.getEnd(), BigInteger.valueOf(gp));
            println("gp = " + Long.toHexString(gp) + " over " + b.getName());
        }
    }
}
