
import ghidra.app.script.GhidraScript;
import ghidra.docking.settings.FormatSettingsDefinition;
import ghidra.program.model.data.*;
public class CreateResizeFields extends GhidraScript {
    public void run() throws Exception {
        var dtm = currentProgram.getDataTypeManager();
        var tail = new StructureDataType(CategoryPath.ROOT, "Tail", 16, dtm);
        tail.setDescription("recovered header");
        tail.replaceAtOffset(0, DWordDataType.dataType, 4, "value", "saved value");
        tail.replaceAtOffset(4, Undefined4DataType.dataType, 4, "unknown", "explicit undefined");
        tail.insertAtOffset(12, new ArrayDataType(ByteDataType.dataType, 0, 1), 0, "boundary", "zero length");
        var saved = (Structure) dtm.addDataType(tail, null);
        FormatSettingsDefinition.DEF.setChoice(saved.getComponentAt(0).getDefaultSettings(), FormatSettingsDefinition.DECIMAL);
        EndianSettingsDefinition.DEF.setChoice(saved.getComponentAt(0).getDefaultSettings(), EndianSettingsDefinition.BIG);
        var flags = new StructureDataType(CategoryPath.ROOT, "Flags", 12, dtm);
        flags.insertBitFieldAt(6, 2, 4, UnsignedShortDataType.dataType, 8, "bits", "spans bytes");
        dtm.addDataType(flags, null);
        var packed = new StructureDataType(CategoryPath.ROOT, "Packed", 0, dtm);
        packed.setPackingEnabled(true);
        packed.add(DWordDataType.dataType, "value", null);
        dtm.addDataType(packed, null);
    }
}
