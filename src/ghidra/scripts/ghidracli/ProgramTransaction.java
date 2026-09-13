package ghidracli;

import ghidra.program.model.listing.Program;

/** A handler transaction tied to the Program on which it was opened. */
final class ProgramTransaction {
    private final Program program;
    private final int id;
    private final boolean nested;
    private boolean ended;

    ProgramTransaction(Program program, String description) {
        this.program = program;
        nested = program.getCurrentTransactionInfo() != null;
        id = program.startTransaction(description);
    }

    void end(boolean commit) {
        if (ended) return;
        ended = true;
        // Ghidra shares one rollback status across nested transactions. Aborting
        // a handler inside the request transaction would discard other changes
        // in that request too. Preserve partial edits as before; earlier
        // requests have already committed and saved. Standalone transactions can abort.
        program.endTransaction(id, commit || nested);
    }
}
