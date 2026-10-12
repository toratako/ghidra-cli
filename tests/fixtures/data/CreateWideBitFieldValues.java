import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.Integer16DataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.UnsignedInteger16DataType;
import ghidra.program.model.symbol.SourceType;

public class CreateWideBitFieldValues extends GhidraScript {
    @Override
    public void run() throws Exception {
        var bits = new StructureDataType("DataWideBits", 32,
            currentProgram.getDataTypeManager());
        bits.insertBitFieldAt(0, 16, 3, Integer16DataType.dataType, 80, "negative", null);
        bits.insertBitFieldAt(16, 16, 3, UnsignedInteger16DataType.dataType, 80, "positive", null);
        byte[] bytes = new byte[32];
        java.util.Arrays.fill(bytes, (byte) 0xff);
        var start = toAddr(0x1840);
        currentProgram.getMemory().setBytes(start, bytes);
        createData(start, bits);
        createLabel(start, "data_wide_bits", true, SourceType.USER_DEFINED);
    }
}
