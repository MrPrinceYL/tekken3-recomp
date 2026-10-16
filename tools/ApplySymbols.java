// Apply the symbols of the shipped linker maps (static.map + foresta.map, relocated by
// rel_link.py into symbols.csv) before auto-analysis: functions in executable blocks get
// disassembled and created at their map address with their map size; everything else becomes a label.
// Usage: ghidra script run ApplySymbols.java -- <symbols.csv>
//@category Analysis
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;

import java.nio.file.*;
import java.util.*;

public class ApplySymbols extends GhidraScript {
    private static List<String> splitCsv(String line) {
        List<String> out = new ArrayList<>();
        StringBuilder b = new StringBuilder();
        boolean q = false;
        for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);
            if (q) {
                if (c == '"' && i + 1 < line.length() && line.charAt(i + 1) == '"') { b.append('"'); i++; }
                else if (c == '"') q = false;
                else b.append(c);
            } else if (c == '"') q = true;
            else if (c == ',') { out.add(b.toString()); b.setLength(0); }
            else b.append(c);
        }
        out.add(b.toString());
        return out;
    }

    @Override
    protected void run() throws Exception {
        Path csv = Paths.get(getScriptArgs()[0]);
        AddressSpace ram = currentProgram.getAddressFactory().getDefaultAddressSpace();
        SymbolTable st = currentProgram.getSymbolTable();
        FunctionManager fm = currentProgram.getFunctionManager();
        Listing listing = currentProgram.getListing();
        int funcs = 0, labels = 0, bad = 0;
        List<String> lines = Files.readAllLines(csv);
        for (String line : lines.subList(1, lines.size())) {
            if (monitor.isCancelled()) break;
            List<String> f = splitCsv(line);
            Address a = ram.getAddress(Long.parseLong(f.get(0).substring(2), 16));
            String name = f.get(1);
            long size = Long.parseLong(f.get(2));
            MemoryBlock b = currentProgram.getMemory().getBlock(a);
            if (b == null) { bad++; continue; }
            try {
                String sec = f.get(3);
                if (b.isExecute() && size > 0 && (sec.equals(".text") || sec.equals(".init"))) {
                    AddressSet body = new AddressSet(a, a.add(size - 1));
                    if (listing.getInstructionAt(a) == null)
                        new DisassembleCommand(body, body, false).applyTo(currentProgram, monitor);
                    Function fn = fm.getFunctionAt(a);
                    if (fn == null) {
                        if (fm.getFunctionsOverlapping(body).hasNext()) {
                            st.createLabel(a, name, SourceType.IMPORTED);
                            labels++;
                            continue;
                        }
                        fn = fm.createFunction(name, a, body, SourceType.IMPORTED);
                    } else {
                        fn.setName(name, SourceType.IMPORTED);
                    }
                    funcs++;
                } else {
                    Symbol s = st.createLabel(a, name, SourceType.IMPORTED);
                    s.setPrimary();
                    labels++;
                }
            } catch (Exception e) {
                bad++;
                if (bad < 40) println("skip " + f.get(0) + " " + name + ": " + e.getMessage());
            }
            if ((funcs + labels) % 10000 == 0) println("applied " + (funcs + labels));
        }
        println("done: " + funcs + " functions, " + labels + " labels, " + bad + " skipped");
    }
}
