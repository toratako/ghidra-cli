
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.CharDataType;
public class AddDenseStringArray extends GhidraScript {
    public void run() throws Exception {
        var start = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(0x65000000);
        currentProgram.getMemory().createInitializedBlock("dense_string", start,
            65536, (byte) 'x', monitor, false);
        currentProgram.getListing().createData(start, new ArrayDataType(CharDataType.dataType, 65536, 1));
    }
}
