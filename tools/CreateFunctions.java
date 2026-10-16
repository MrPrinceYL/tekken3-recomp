// Create functions at the addresses listed in a CSV (first column `addr`, hex), e.g. resident
// functions that only overlay code calls (extracted/resident_seeds.csv from bns_overlays.py).
// Usage: ghidra script run CreateFunctions.java -- <csv>
//@category Analysis
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;

import java.nio.file.*;
import java.util.*;

public class CreateFunctions extends GhidraScript {
    @Override
    protected void run() throws Exception {
        List<String> lines = Files.readAllLines(Paths.get(getScriptArgs()[0]));
        FunctionManager fm = currentProgram.getFunctionManager();
        Listing listing = currentProgram.getListing();
        int created = 0, existed = 0, failed = 0;
        for (String line : lines.subList(1, lines.size())) {
            Address a = toAddr(line.split(",")[0].trim());
            if (fm.getFunctionAt(a) != null) { existed++; continue; }
            // A function that wrongly swallowed this address keeps it otherwise.
            Function host = fm.getFunctionContaining(a);
            if (listing.getInstructionAt(a) == null) {
                if (listing.getDefinedDataAt(a) != null) listing.clearCodeUnits(a, a, false);
                new DisassembleCommand(a, null, true).applyTo(currentProgram, monitor);
            }
            if (new CreateFunctionCmd(a).applyTo(currentProgram, monitor)) {
                created++;
                if (host != null) CreateFunctionCmd.fixupFunctionBody(currentProgram, host, monitor);
            } else {
                failed++;
                println("could not create a function at " + a);
            }
        }
        println("done: " + created + " created, " + existed + " existed, " + failed + " failed");
    }
}
