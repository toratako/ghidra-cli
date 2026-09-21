package ghidracli;

import com.google.gson.JsonObject;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraState;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.util.GhidraProgramUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;

/** Live view of script state; never caches a Program or a per-job monitor. */
final class ProgramSession {
    private final ScriptAccess script;
    private final Object consumer = new Object();
    private final DecompilerSession decompiler = new DecompilerSession();
    private ProgramTransaction requestTransaction;
    private boolean requestActive;
    private boolean atomicRequest;
    private long requestModification;
    private SaveFailure saveFailure;
    private JsonProtocol.CommandException requestFailure;

    record RequestOutcome(boolean saved, boolean rolledBack, boolean cancelled) {}

    /** Saving failed after transaction completion; edits must not be replayed. */
    static final class SaveFailure extends Exception {
        SaveFailure(Exception cause) { super(cause.getMessage(), cause); }
    }

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
    DecompileResults decompile(Function function, int timeoutSecs) throws CancelledException {
        return decompiler.decompile(program(), function, timeoutSecs, monitor());
    }
    private ProgramTransaction transaction(String description) {
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
        GhidraProgramUtilities.markProgramAnalyzed(program());
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
            if (isProgramFile(file)) files.add(file);
        }
        for (DomainFolder child : folder.getFolders()) appendProgramFiles(child, files);
    }

    private static boolean isProgramFile(DomainFile file) {
        Class<? extends DomainObject> objectClass = file.getDomainObjectClass();
        return objectClass != null && Program.class.isAssignableFrom(objectClass);
    }

    void beginRequest(String command) {
        if (requestActive) throw transactionFailure("A program request is already active");
        // Atomic by default, including future ordinary commands. These explicit
        // exceptions have analysis, arbitrary-script, project or filesystem effects.
        boolean atomic = switch (command == null ? "" : command) {
            case "analysis_run", "script_run", "import", "program_export",
                 "open_program", "program_close", "program_save", "program_delete" -> false;
            default -> true;
        };
        if (atomic && program() != null && program().getCurrentTransactionInfo() != null) {
            throw transactionFailure("Cannot start an atomic command while another transaction is active. "
                + "Close the transaction through its owning script, then retry; it has not been ended or modified.");
        }
        saveFailure = null;
        requestFailure = null;
        atomicRequest = atomic;
        requestActive = true;
        try {
            startRequestTransaction("ghidra-cli: " + command);
        } catch (RuntimeException failure) {
            requestActive = false;
            atomicRequest = false;
            throw transactionFailure("Could not start command transaction: " + failure.getMessage());
        }
    }

    private void startRequestTransaction(String description) {
        if (program() != null) {
            requestTransaction = transaction(description);
            requestModification = program().getModificationNumber();
        }
    }

    private void endRequestTransaction(boolean commit) {
        if (requestTransaction != null) {
            requestTransaction.end(commit);
            requestTransaction = null;
            if (!commit && program().getCurrentTransactionInfo() != null) {
                requestFailure = transactionFailure("Rollback is pending an unclosed transaction. "
                    + "Keep the bridge running and close that transaction through its owning script. "
                    + "The command's changes must not be saved or replayed.");
                throw requestFailure;
            }
        }
    }

    private static JsonProtocol.CommandException transactionFailure(String message) {
        JsonObject detail = new JsonObject();
        detail.addProperty("transaction_failed", true);
        return new JsonProtocol.CommandException(message, detail);
    }

    /**
     * Run a program-only preview in its own rollback transaction. The caller must
     * not have changed this request's Program or switch programs. End only the
     * untouched request transaction; never commit preceding edits to allow a preview.
     * Return detached values, never listing objects invalidated by rollback.
     */
    <T> T preview(String description, Callable<T> operation) throws Exception {
        var info = program().getCurrentTransactionInfo();
        if (!requestActive || !atomicRequest || requestTransaction == null
                || !requestTransaction.isSoleOwner() || info == null) {
            throw new IllegalStateException("Preview requires the sole owned request transaction");
        }
        if (program().getModificationNumber() != requestModification) {
            throw new IllegalStateException("Preview must run before any changes in the request");
        }
        String requestDescription = info.getDescription();
        endRequestTransaction(false);
        // Keep ownership visible to request cleanup if the native preview leaks
        // an additional transaction and cannot be rolled back immediately.
        requestTransaction = transaction(description);
        try {
            return operation.call();
        } finally {
            endRequestTransaction(false);
            startRequestTransaction(requestDescription);
        }
    }

    RequestOutcome finishRequest(boolean successful) throws Exception {
        try {
            if (requestFailure != null) throw requestFailure;
            boolean cancelled = atomicRequest && monitor().isCancelled();
            boolean rolledBack = false;
            if (requestTransaction != null) {
                if (atomicRequest && !requestTransaction.isSoleOwner()) {
                    // Mark only our owned root for rollback. Never commit a
                    // failed atomic edit simply because native code leaked a child.
                    endRequestTransaction(false);
                    throw transactionFailure("The command left another transaction active; "
                        + "rollback and saving could not complete. Keep the bridge running and close "
                        + "that transaction through its owner before retrying program save.");
                }
                rolledBack = atomicRequest
                    && (!successful || cancelled || requestTransaction.isAborted());
                endRequestTransaction(!rolledBack);
            }
            if (saveFailure != null) throw saveFailure;
            // A rejected edit must not save unrelated, pending edits from an
            // earlier save failure. They remain available for explicit recovery.
            return new RequestOutcome(!rolledBack && save(), rolledBack, cancelled);
        } finally {
            requestActive = false;
            atomicRequest = false;
        }
    }

    /** Flush committed changes before acknowledging a request or releasing a program. */
    boolean save() throws Exception {
        if (requestActive && requestFailure != null) throw requestFailure;
        if (requestActive && saveFailure != null) throw saveFailure;
        if (requestActive && atomicRequest && requestTransaction != null) {
            throw transactionFailure("Cannot save before an atomic request has finished");
        }
        try {
            endRequestTransaction(true);
            if (program() == null) return false;
            if (program().getCurrentTransactionInfo() != null) {
                throw new IllegalStateException("Program still has an active transaction");
            }
            if (!program().isChanged()) return false;
            // Cancellation never interrupts durable saving after a commit.
            program().save("ghidra-cli auto-save", TaskMonitor.DUMMY);
            if (program().isChanged()) {
                throw new IllegalStateException("Program still has unsaved changes");
            }
            return true;
        } catch (Exception failure) {
            SaveFailure error = failure instanceof SaveFailure
                ? (SaveFailure) failure : new SaveFailure(failure);
            if (requestActive) saveFailure = error;
            throw error;
        }
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
        decompiler.close();
        if (program() != null) program().release(consumer);
        setProgram((Program) domObj);
        if (requestActive) startRequestTransaction("ghidra-cli: open program");
    }

    void closeProgram() throws Exception {
        save();
        decompiler.close();
        if (program() != null) program().release(consumer);
        setProgram(null);
    }

    void delete(DomainFile file) throws Exception {
        if (!isProgramFile(file)) {
            throw new IllegalArgumentException("Project file is not a program: " + file.getPathname());
        }
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
