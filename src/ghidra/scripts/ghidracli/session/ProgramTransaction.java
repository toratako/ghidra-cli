package ghidracli.session;

import ghidra.framework.model.TransactionInfo;
import ghidra.program.model.listing.Program;

/** An owned transaction entry; only the outermost owner can roll back. */
public final class ProgramTransaction {
    private final Program program;
    private final int id;
    private final boolean outermost;
    private final TransactionInfo info;
    private boolean ended;

    public ProgramTransaction(Program program, String description) {
        this.program = program;
        outermost = program.getCurrentTransactionInfo() == null;
        id = program.startTransaction(description);
        info = program.getCurrentTransactionInfo();
    }

    private boolean ownsCurrentRoot() {
        TransactionInfo current = program.getCurrentTransactionInfo();
        return !ended && outermost && current != null && current.getID() == info.getID();
    }

    boolean isSoleOwner() {
        return ownsCurrentRoot()
            && program.getCurrentTransactionInfo().getOpenSubTransactions().size() == 1;
    }

    boolean isAborted() {
        return info.getStatus() == TransactionInfo.Status.ABORTED
            || info.getStatus() == TransactionInfo.Status.NOT_DONE_BUT_ABORTED;
    }

    public void end(boolean commit) {
        if (ended) throw new IllegalStateException("Transaction already ended");
        if (!commit && !ownsCurrentRoot()) {
            throw new IllegalStateException("Rollback requires ownership of the outermost transaction");
        }
        // Never turn an abort into a commit. Native nested operations participate
        // in this transaction; their failures must be handled by its outer owner.
        // If native code leaked a child, abort only our known root entry. Ghidra
        // will finish the rollback once that child's owner closes it; callers
        // must not report a completed rollback while any entry remains active.
        program.endTransaction(id, commit);
        ended = true;
    }
}
