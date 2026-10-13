
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
public class CreateBitEditFixtures extends GhidraScript {
    public void run() throws Exception {
        var dtm = currentProgram.getDataTypeManager();
        var bits = new StructureDataType("Bits", 12, dtm);
        bits.replaceAtOffset(8, DWordDataType.dataType, 4, "tail", "keep tail");
        dtm.addDataType(bits, null);
        var enumeration = new EnumDataType(CategoryPath.ROOT, "FlagsEnum", 4, dtm);
        enumeration.add("flag", 1);
        dtm.addDataType(enumeration, null);
        dtm.addDataType(new TypedefDataType(CategoryPath.ROOT, "Word", UnsignedIntegerDataType.dataType, dtm), null);
    }
}
