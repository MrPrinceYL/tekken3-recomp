// Run Ghidra's auto-analysis on the current program (all enabled analyzers, as on import).
// Used instead of `ghidra analyze`, which fails in ghidra-cli once its bridge has worked on
// another program ("Transaction has not been started").
// Usage: ghidra script run Analyze.java
//@category Analysis
import ghidra.app.script.GhidraScript;

public class Analyze extends GhidraScript {
    @Override
    protected void run() throws Exception {
        analyzeAll(currentProgram);
        println("analyzed: " + currentProgram.getFunctionManager().getFunctionCount() + " functions");
    }
}
