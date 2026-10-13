
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.UnsignedIntegerDataType;
public class CreateSpecialFieldFixtures extends GhidraScript {
    public void run() throws Exception {
        var dtm = currentProgram.getDataTypeManager();
        String prefix = getScriptArgs()[0];
        var packed = new StructureDataType(CategoryPath.ROOT, prefix + "Packed", 0, dtm);
        packed.setPackingEnabled(true);
        packed.add(ByteDataType.dataType, "tag", "tag comment");
        packed.add(IntegerDataType.dataType, "value", "value comment");
        dtm.addDataType(packed, null);
        var bits = new StructureDataType(CategoryPath.ROOT, prefix + "Bits", 0, dtm);
        bits.addBitField(UnsignedIntegerDataType.dataType, 3, "flags", "bit comment");
        dtm.addDataType(bits, null);
        var zero = new StructureDataType(CategoryPath.ROOT, prefix + "Zero", 0, dtm);
        zero.add(ByteDataType.dataType, "start", null);
        zero.add(new ArrayDataType(ByteDataType.dataType, 0, -1, dtm), "zero", "empty");
        zero.add(ByteDataType.dataType, "end", null);
        dtm.addDataType(zero, null);
    }
}
