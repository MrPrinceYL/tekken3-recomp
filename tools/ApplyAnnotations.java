// Apply the hand-written annotations from the sheets to one program: function names and their
// summaries (plate comments), global variable names / types / comments, parameter and local
// variable names, and comments on individual instructions. Names and comments only: the code
// bytes, the disassembly and the p-code export are unchanged by this script.
//
// Usage: ghidra script run ApplyAnnotations.java -- <sheets dir> <variant>
//   Function, global and comment rows of variant `resident` apply to every program (each one
//   contains the resident executable, so calls into it read well); rows of <variant>, and all
//   variable renames, apply to that program only.
//
// Sheets read (all optional):
//   manual_names.csv    variant,addr,name,status,evidence[,section,summary]
//   manual_globals.csv  variant,addr,name,type,comment
//   manual_vars.csv     variant,func,old_name,new_name,type    (old_name as Ghidra shows it)
//   manual_comments.csv variant,addr,comment                     (shown above that line in the C)
//@category Annotation
import ghidra.app.decompiler.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.*;
import ghidra.util.data.DataTypeParser;

import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

public class ApplyAnnotations extends GhidraScript {
    private String variant;
    private int applied, failed;

    /** Minimal CSV reader (quoted fields, doubled quotes, commas inside quotes). */
    private List<Map<String, String>> csv(Path p) throws Exception {
        List<Map<String, String>> rows = new ArrayList<>();
        if (!Files.exists(p)) return rows;
        String text = Files.readString(p, StandardCharsets.UTF_8);
        List<List<String>> recs = new ArrayList<>();
        List<String> rec = new ArrayList<>();
        StringBuilder f = new StringBuilder();
        boolean q = false;
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (q) {
                if (c == '"' && i + 1 < text.length() && text.charAt(i + 1) == '"') { f.append('"'); i++; }
                else if (c == '"') q = false;
                else f.append(c);
            } else if (c == '"') q = true;
            else if (c == ',') { rec.add(f.toString()); f.setLength(0); }
            else if (c == '\n') { rec.add(f.toString()); f.setLength(0); recs.add(rec); rec = new ArrayList<>(); }
            else if (c != '\r') f.append(c);
        }
        if (f.length() > 0 || !rec.isEmpty()) { rec.add(f.toString()); recs.add(rec); }
        if (recs.isEmpty()) return rows;
        List<String> head = recs.get(0);
        for (List<String> r : recs.subList(1, recs.size())) {
            if (r.size() == 1 && r.get(0).isEmpty()) continue;
            Map<String, String> m = new HashMap<>();
            for (int i = 0; i < head.size(); i++) m.put(head.get(i), i < r.size() ? r.get(i) : "");
            rows.add(m);
        }
        return rows;
    }

    private boolean mine(Map<String, String> r) {
        String v = r.getOrDefault("variant", "");
        return v.equals("resident") || v.equals(variant);
    }

    private DataType type(String name) {
        if (name == null || name.isBlank()) return null;
        try {
            DataTypeParser p = new DataTypeParser(currentProgram.getDataTypeManager(), null, null,
                DataTypeParser.AllowedDataTypes.ALL);
            return p.parse(name.trim());
        } catch (Exception e) {
            println("unknown type '" + name + "': " + e.getMessage());
            failed++;
            return null;
        }
    }

    @Override
    protected void run() throws Exception {
        Path sheets = Paths.get(getScriptArgs()[0]);
        variant = getScriptArgs()[1];
        FunctionManager fm = currentProgram.getFunctionManager();
        Listing listing = currentProgram.getListing();
        SymbolTable st = currentProgram.getSymbolTable();

        // 1. Function names and summaries.
        for (Map<String, String> r : csv(sheets.resolve("manual_names.csv"))) {
            if (!mine(r)) continue;
            Function f = fm.getFunctionAt(toAddr(r.get("addr")));
            if (f == null) { failed++; println("no function at " + r.get("addr")); continue; }
            String name = r.get("name");
            if (!f.getName().equals(name)) {
                // A plain label of the same name at the entry (e.g. __start from the BIOS stub
                // symbols) would make the rename fail: the function name replaces it.
                for (Symbol s : st.getSymbols(f.getEntryPoint()))
                    if (s.getName().equals(name) && s.getSymbolType() == SymbolType.LABEL) s.delete();
                f.setName(name, SourceType.USER_DEFINED);
            }
            StringBuilder plate = new StringBuilder();
            String section = r.getOrDefault("section", ""), summary = r.getOrDefault("summary", "");
            if (!section.isEmpty()) plate.append("[").append(section).append("] ");
            plate.append(summary.isEmpty() ? r.getOrDefault("evidence", "") : summary);
            if (plate.length() > 0) f.setComment(plate.toString());
            applied++;
        }

        // 2. Global variables.
        for (Map<String, String> r : csv(sheets.resolve("manual_globals.csv"))) {
            if (!mine(r)) continue;
            Address a = toAddr(r.get("addr"));
            if (!currentProgram.getMemory().contains(a)) continue;
            Symbol s = st.getPrimarySymbol(a);
            if (s != null && s.getSource() != SourceType.DEFAULT) s.setName(r.get("name"), SourceType.USER_DEFINED);
            else st.createLabel(a, r.get("name"), SourceType.USER_DEFINED).setPrimary();
            DataType t = type(r.get("type"));
            if (t != null) {
                try {
                    listing.clearCodeUnits(a, a.add(Math.max(t.getLength(), 1) - 1), false);
                    listing.createData(a, t);
                } catch (Exception e) { println("type at " + a + ": " + e.getMessage()); failed++; }
            }
            String c = r.getOrDefault("comment", "");
            if (!c.isEmpty()) listing.setComment(a, CommentType.PLATE, c);
            applied++;
        }

        // 3. Comments on instructions (PRE comments: the decompiler prints them above the line).
        for (Map<String, String> r : csv(sheets.resolve("manual_comments.csv"))) {
            if (!mine(r)) continue;
            Address a = toAddr(r.get("addr"));
            if (listing.getInstructionAt(a) == null) { failed++; println("no instruction at " + a); continue; }
            listing.setComment(a, CommentType.PRE, r.get("comment"));
            applied++;
        }

        // 4. Parameters and locals, through the decompiler's view of each function.
        Map<String, List<Map<String, String>>> byFunc = new TreeMap<>();
        // Only in the function's own program: a function's C is exported from there, and the
        // decompiler's automatic local names differ between programs.
        for (Map<String, String> r : csv(sheets.resolve("manual_vars.csv")))
            if (r.getOrDefault("variant", "").equals(variant))
                byFunc.computeIfAbsent(r.get("func").toUpperCase(), k -> new ArrayList<>()).add(r);
        if (!byFunc.isEmpty()) {
            DecompInterface di = new DecompInterface();
            di.setOptions(new DecompileOptions());
            di.openProgram(currentProgram);
            for (Map.Entry<String, List<Map<String, String>>> e : byFunc.entrySet()) {
                Function f = fm.getFunctionAt(toAddr(e.getKey()));
                if (f == null) { failed++; println("vars: no function at " + e.getKey()); continue; }
                for (Map<String, String> r : e.getValue()) {
                    // Decompile again after each change: renaming commits the variable to the
                    // database, which can change the names of the others.
                    DecompileResults res = di.decompileFunction(f, 60, monitor);
                    HighFunction hf = res.getHighFunction();
                    if (hf == null) { failed++; break; }
                    HighSymbol sym = null;
                    boolean done = false;
                    Iterator<HighSymbol> it = hf.getLocalSymbolMap().getSymbols();
                    while (it.hasNext()) {
                        HighSymbol s = it.next();
                        if (s.getName().equals(r.get("old_name"))) sym = s;
                        if (s.getName().equals(r.get("new_name"))) done = true;
                    }
                    // Renamed by an earlier run: the decompiler may since have given the old
                    // automatic name to another variable, which must not be renamed too.
                    if (done) continue;
                    if (sym == null) {
                        failed++;
                        println("vars: " + f.getName() + " has no " + r.get("old_name"));
                        continue;
                    }
                    DataType t = type(r.getOrDefault("type", ""));
                    HighFunctionDBUtil.updateDBVariable(sym, r.get("new_name"), t, SourceType.USER_DEFINED);
                    applied++;
                }
            }
            di.dispose();
        }
        println("done: " + applied + " annotations applied, " + failed + " failed (" + variant + ")");
    }
}
