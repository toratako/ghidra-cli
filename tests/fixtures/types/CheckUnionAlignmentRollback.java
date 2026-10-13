
import ghidra.app.script.GhidraScript;
public class CheckUnionAlignmentRollback extends GhidraScript {
    public void run() throws Exception {
        for (int address : new int[] { 0x1000, 0x1100 }) {
            var data = currentProgram.getListing().getDefinedDataAt(toAddr(address));
            if (data == null || data.getLength() != 10 || data.getDataType().getLength() != 10)
                throw new IllegalStateException("Union alignment left incomplete applied data");
        }
    }
}
