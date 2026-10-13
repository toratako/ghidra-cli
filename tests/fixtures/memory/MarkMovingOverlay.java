
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.CodeUnit;
public class MarkMovingOverlay extends GhidraScript {
    public void run() throws Exception {
        var address = currentProgram.getAddressFactory().getAddressSpace("bank")
            .getAddressInThisSpaceOnly(0x2000);
        currentProgram.getListing().setComment(address, CodeUnit.EOL_COMMENT, "overlay comment");
    }
}
