package ghidracli;

import ghidra.program.model.listing.Program;

/** A handler transaction tied to the Program on which it was opened. */
final class ProgramTransaction {
    private final Program program;
    private final int id;

    ProgramTransaction(Program program, String description) {
        this.program = program;
        id = program.startTransaction(description);
    }

    void end(boolean commit) {
        program.endTransaction(id, commit);
    }
}
