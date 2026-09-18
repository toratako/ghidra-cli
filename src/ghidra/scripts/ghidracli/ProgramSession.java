package ghidracli;

import ghidra.app.script.GhidraState;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.util.GhidraProgramUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/** Live view of script state; never caches a Program or a per-job monitor. */
final class ProgramSession {
    private final ScriptAccess script;
    private final Object consumer = new Object();
    private ProgramTransaction requestTransaction;
    private boolean requestActive;
    private Exception exportSaveFailure;

    ProgramSession(ScriptAccess script) {
        this.script = script;
        if (program() != null) program().addConsumer(consumer);
    }

    Program program() { return script.program(); }
    private DomainFile programFile() {
        Program current = program();
        return current == null ? null : current.getDomainFile();
    }
    /** CLI identity follows the project file, including renamed/copied programs. */
    String programName() {
        DomainFile file = programFile();
        return file == null ? null : file.getName();
    }
    String programPath() {
        DomainFile file = programFile();
        return file == null ? null : file.getPathname();
    }
    private void setProgram(Program program) { script.setProgram(program); }
    GhidraState state() { return script.state(); }
    TaskMonitor monitor() { return script.monitor(); }
    void setMonitor(TaskMonitor monitor) { script.setMonitor(monitor); }
    ProgramTransaction transaction(String description) {
        return new ProgramTransaction(program(), description);
    }
    boolean disassemble(Address address) throws Exception { return script.disassemble(address); }
    void analyzeAll() throws CancelledException {
        monitor().checkCancelled();
        // Ghidra's analyzeAll initializes analyzer options and schedules full
        // reanalysis itself; do not call reAnalyzeAll separately.
        script.analyzeAll(program());
        // Ghidra's analysis entry point can return normally after cancellation.
        // Preserve an earlier completed analysis flag, but never create one for
        // the cancelled first run.
        monitor().checkCancelled();
        ProgramTransaction transaction = transaction("Record completed analysis");
        try {
            GhidraProgramUtilities.markProgramAnalyzed(program());
            transaction.end(true);
        } catch (RuntimeException failure) {
            transaction.end(false);
            throw failure;
        }
    }
    void clearListing(Address start, Address end) throws Exception { script.clearListing(start, end); }

    /** Shared project-file traversal for program list and control snapshots. */
    List<DomainFile> programFiles() throws CancelledException {
        List<DomainFile> files = new ArrayList<>();
        appendProgramFiles(state().getProject().getProjectData().getRootFolder(), files);
        return files;
    }

    private void appendProgramFiles(DomainFolder folder, List<DomainFile> files)
            throws CancelledException {
        monitor().checkCancelled();
        for (DomainFile file : folder.getFiles()) {
            monitor().checkCancelled();
            Class<? extends DomainObject> objectClass = file.getDomainObjectClass();
            if (objectClass != null && Program.class.isAssignableFrom(objectClass)) files.add(file);
        }
        for (DomainFolder child : folder.getFolders()) appendProgramFiles(child, files);
    }

    void beginRequest(String command) {
        exportSaveFailure = null;
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
        if (exportSaveFailure != null) {
            Exception failure = exportSaveFailure;
            exportSaveFailure = null;
            throw failure;
        }
        return save();
    }

    /** Packed export requires a saved program with no active transaction. */
    void preparePackedExport() throws Exception {
        try {
            save();
        } catch (Exception failure) {
            // Preserve the first save failure for the dispatcher's save_failed
            // response instead of implicitly retrying it at request completion.
            exportSaveFailure = failure;
            throw failure;
        }
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
        try {
            // HeadlessAnalyzer normally initializes these before its preScript.
            // Script-only startup must register analyzer options on every open.
            ghidra.app.plugin.core.analysis.AutoAnalysisManager.getAnalysisManager((Program) domObj)
                .initializeOptions();
        } catch (Exception failure) {
            domObj.release(consumer);
            throw failure;
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

    void delete(DomainFile file) throws Exception {
        boolean wasCurrent = isCurrent(file);
        if (wasCurrent) closeProgram();
        try {
            file.delete();
        } catch (Exception failure) {
            // Do not release other consumers or terminate checkouts. Restore
            // our selection when Ghidra refuses to delete the closed file.
            if (wasCurrent) {
                try {
                    open(file);
                } catch (Exception reopenFailure) {
                    throw new IOException(failure.getMessage() + "; failed to reopen "
                        + file.getPathname() + ": " + reopenFailure.getMessage(), failure);
                }
            }
            throw failure;
        }
    }
}
