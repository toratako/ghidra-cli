
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.CommentType;
public class ChangeVariableSelectionRevision extends GhidraScript {
    public void run() {
        currentProgram.getListing().setComment(toAddr(0x1000), CommentType.EOL, "revision changed");
    }
}
