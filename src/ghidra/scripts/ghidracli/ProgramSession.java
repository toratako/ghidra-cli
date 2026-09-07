package ghidracli;

import ghidra.app.script.GhidraState;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainObject;
import ghidra.framework.model.Project;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

/** Live view of script state; never caches a Program or a per-job monitor. */
final class ProgramSession {
    private final ScriptAccess script;

    ProgramSession(ScriptAccess script) {
        this.script = script;
    }

    Program program() { return script.program(); }
    private void setProgram(Program program) { script.setProgram(program); }
    GhidraState state() { return script.state(); }
    TaskMonitor monitor() { return script.monitor(); }
    void setMonitor(TaskMonitor monitor) { script.setMonitor(monitor); }
    ProgramTransaction transaction(String description) {
        return new ProgramTransaction(program(), description);
    }
    boolean disassemble(Address address) throws Exception { return script.disassemble(address); }
    void analyzeAll(Program program) { script.analyzeAll(program); }
    void clearListing(Address start, Address end) throws Exception { script.clearListing(start, end); }
    void logError(String message) { script.logError(message); }

    /** Switch a program using the project's existing consumer identity. */
    void open(DomainFile domainFile, Project project) throws Exception {
        Object consumer = project;
        TaskMonitor mon = monitor();

        // Release current program if one is open
        if (program() != null) {
            try {
                program().save("Auto-save before switch", mon);
            } catch (Exception e) {
                // Best effort save
            }
            try {
                program().release(consumer);
            } catch (Exception e) {
                // Best effort release
            }
        }

        // Open the requested program
        DomainObject domObj = domainFile.getDomainObject(consumer, true, false, mon);
        if (domObj instanceof Program) {
            setProgram((Program) domObj);
        }
    }

    void closeProgram() {
        // The initially loaded program is held by the headless harness too.
        // Its pending transaction is saved when the script returns, not here.
        try {
            Project project = state().getProject();
            if (project != null) program().release(project);
        } catch (Exception ignored) {
            // Preserve best-effort release for a program owned by the harness.
        }
        setProgram(null);
    }
}
