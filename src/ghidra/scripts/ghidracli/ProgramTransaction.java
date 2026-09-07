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
        // a handler inside the headless script transaction would discard earlier
        // successful requests too. Preserve those edits, even if the failed
        // request left partial changes. Standalone transactions can still abort.
        program.endTransaction(id, commit || nested);
    }
}
