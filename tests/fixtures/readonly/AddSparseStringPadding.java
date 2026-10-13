
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.StructureDataType;
public class AddSparseStringPadding extends GhidraScript {
    public void run() throws Exception {
        int length = 128 * 1024 * 1024;
        var start = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(0x70000000);
        currentProgram.getMemory().createUninitializedBlock("padding", start, length - 8, false);
        currentProgram.getMemory().createInitializedBlock("tail_string", start.add(length - 8),
            8, (byte) 'x', monitor, false);
        var sparse = new StructureDataType("SparseStringPadding", length);
        sparse.replaceAtOffset(length - 8, new ArrayDataType(CharDataType.dataType, 8, 1),
            8, "text", null);
        currentProgram.getListing().createData(start, sparse);
    }
}
