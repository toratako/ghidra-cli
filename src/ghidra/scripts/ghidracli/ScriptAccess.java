package ghidracli;

import ghidra.app.script.GhidraState;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

/**
 * Access to the owning GhidraScript. Program, state, and monitor operations are
 * confined to its original thread; network threads may only call logError.
 */
public interface ScriptAccess {
    Program program();
    void setProgram(Program program);
    GhidraState state();
    TaskMonitor monitor();
    void setMonitor(TaskMonitor monitor);
    boolean disassemble(Address address) throws Exception;
    void analyzeAll(Program program);
    void clearListing(Address start, Address end) throws Exception;
    void logError(String message);
}
