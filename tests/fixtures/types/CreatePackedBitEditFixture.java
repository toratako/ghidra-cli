import ghidra.app.script.GhidraScript;
import ghidra.docking.settings.FormatSettingsDefinition;
import ghidra.program.model.data.*;

public class CreatePackedBitEditFixture extends GhidraScript {
  public void run() throws Exception {
    var dtm = currentProgram.getDataTypeManager();
    var packed = new StructureDataType("PackedBits", 0, dtm);
    packed.setPackingEnabled(true);
    packed.addBitField(UnsignedIntegerDataType.dataType, 3, "first", "keep");
    packed.addBitField(UnsignedIntegerDataType.dataType, 0, null, "boundary");
    packed.addBitField(UnsignedIntegerDataType.dataType, 4, "last", null);
    var saved = (Structure) dtm.addDataType(packed, null);
    FormatSettingsDefinition.DEF.setChoice(
        saved.getComponent(0).getDefaultSettings(), FormatSettingsDefinition.DECIMAL);
  }
}
