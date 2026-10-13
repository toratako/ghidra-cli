
import ghidra.app.script.GhidraScript;
public class CheckConstrainedImportApplication extends GhidraScript {
    public void run() throws Exception {
        var listing = currentProgram.getListing();
        var data = listing.getDefinedDataAt(toAddr(0x1000));
        var neighbor = listing.getDefinedDataAt(toAddr(0x1004));
        if (data == null || data.getLength() != 4 || data.getDataType().getLength() != 4
                || neighbor == null || neighbor.getLength() != 4)
            throw new IllegalStateException("Import changed constrained applied data");
    }
}
