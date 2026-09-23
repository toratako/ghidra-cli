// Ghidra CLI Bridge - persistent TCP server inside Ghidra
// @category Bridge

import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraState;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import ghidracli.runtime.BridgeRuntime;
import ghidracli.session.ScriptAccess;

/** Persistent bridge entry point; bootstrap uses a separate short-lived script. */
public class GhidraCliBridge extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            printerr("Usage: GhidraCliBridge.java <port_file_path> [<program>]");
            return;
        }
        // GhidraScript.executeNormal() starts a transaction before run(). End
        // our own transaction before serving requests so each request can save.
        // end() also clears the script's transaction ID for normal cleanup.
        end(true);
        BridgeRuntime.run(new ScriptAccess() {
            public Program program() { return currentProgram; }
            public void setProgram(Program program) {
                currentProgram = program;
                state.setCurrentProgram(program);
            }
            public GhidraState state() { return state; }
            public TaskMonitor monitor() { return monitor; }
            public void setMonitor(TaskMonitor value) { monitor = value; }
            public boolean disassemble(Address address) throws Exception {
                return GhidraCliBridge.this.disassemble(address);
            }
            public void analyzeAll(Program program) {
                GhidraCliBridge.this.analyzeAll(program);
            }
            public void analyzeChanges(Program program) {
                GhidraCliBridge.this.analyzeChanges(program);
            }
            public void clearListing(Address start, Address end) throws Exception {
                GhidraCliBridge.this.clearListing(start, end);
            }
            public void logError(String message) { printerr(message); }
        }, args[0], args.length > 1 ? args[1] : null, this::println);
    }
}
