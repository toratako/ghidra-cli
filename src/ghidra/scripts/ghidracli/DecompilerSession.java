package ghidracli;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/** One lazy native decompiler, owned by ProgramSession on the program thread. */
final class DecompilerSession {
    private DecompInterface decompiler;
    private long modification;

    DecompileResults decompile(Program program, Function function, int timeoutSecs,
            TaskMonitor monitor) throws CancelledException {
        boolean completed = false;
        try {
            monitor.checkCancelled();
            if (decompiler != null && (decompiler.getProgram() != program
                    || modification != program.getModificationNumber())) {
                close();
            }
            if (decompiler == null) {
                decompiler = new DecompInterface();
                decompiler.setOptions(new DecompileOptions());
                if (!decompiler.openProgram(program)) {
                    throw new IllegalStateException("Could not open program in decompiler: "
                        + decompiler.getLastMessage());
                }
                // Includes changes made by scripts, analysis and rollback, even
                // after saving clears Program.isChanged(). Reopening also refreshes
                // language/address-space state that flushCache alone cannot fix.
                modification = program.getModificationNumber();
            }
            // Results belong to this call only. Ghidra flushes native function and
            // symbol data after decompilation; retain the process and initialization.
            DecompileResults results = decompiler.decompileFunction(function, timeoutSecs, monitor);
            monitor.checkCancelled();
            completed = results.decompileCompleted();
            return results;
        } finally {
            // Failed initialization, native failures and cancellation must not
            // retain a broken process or affect a subsequent request's monitor.
            if (!completed) close();
        }
    }

    void close() {
        if (decompiler == null) return;
        DecompInterface closing = decompiler;
        decompiler = null;
        // dispose() alone defers closing to Ghidra's disposer thread. Detach
        // synchronously before ProgramSession releases the Program consumer.
        try {
            closing.closeProgram();
        } finally {
            closing.dispose();
        }
    }
}
