package ghidracli;

import ghidra.app.script.GhidraState;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

/** Live view of script state; never caches a Program or a per-job monitor. */
final class ProgramSession {
    private final ScriptAccess script;
    private final Object consumer = new Object();
    private ProgramTransaction requestTransaction;
    private boolean requestActive;

    ProgramSession(ScriptAccess script) {
        this.script = script;
        if (program() != null) program().addConsumer(consumer);
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

    void beginRequest(String command) {
        requestActive = true;
        if (program() != null) requestTransaction = transaction("ghidra-cli: " + command);
    }

    private void endRequestTransaction() {
        if (requestTransaction != null) {
            requestTransaction.end(true);
            requestTransaction = null;
        }
    }

    boolean finishRequest() throws Exception {
        requestActive = false;
        return save();
    }

    /** Flush committed changes before acknowledging a request or releasing a program. */
    boolean save() throws Exception {
        endRequestTransaction();
        if (program() == null) return false;
        if (program().getCurrentTransactionInfo() != null) {
            throw new IllegalStateException("Program still has an active transaction");
        }
        if (!program().isChanged()) return false;
        // A cancelled command can retain partial edits. Cancellation must not
        // interrupt their durable save after the request transaction has ended.
        program().save("ghidra-cli auto-save", TaskMonitor.DUMMY);
        if (program().isChanged()) {
            throw new IllegalStateException("Program still has unsaved changes");
        }
        return true;
    }

    boolean isCurrent(DomainFile domainFile) {
        return program() != null
            && program().getDomainFile().getPathname().equals(domainFile.getPathname());
    }

    /** Save before switching; keep the old program if saving or opening fails. */
    void open(DomainFile domainFile) throws Exception {
        // Program names are stored inside the database and can be identical in
        // different project files (for example after copying a program).
        if (isCurrent(domainFile)) return;
        TaskMonitor mon = monitor();
        save();
        DomainObject domObj = domainFile.getDomainObject(consumer, true, false, mon);
        if (!(domObj instanceof Program)) {
            domObj.release(consumer);
            throw new IllegalArgumentException("Project file is not a program: " + domainFile.getPathname());
        }
        if (program() != null) program().release(consumer);
        setProgram((Program) domObj);
        if (requestActive) requestTransaction = transaction("ghidra-cli: open program");
    }

    void closeProgram() throws Exception {
        save();
        if (program() != null) program().release(consumer);
        setProgram(null);
    }
}
