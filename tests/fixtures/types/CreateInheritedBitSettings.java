import ghidra.app.script.GhidraScript;
import ghidra.docking.settings.FormatSettingsDefinition;
import ghidra.program.model.data.*;

public class CreateInheritedBitSettings extends GhidraScript {
  public void run() throws Exception {
    var dtm = currentProgram.getDataTypeManager();
    var word =
        dtm.addDataType(
            new TypedefDataType(
                CategoryPath.ROOT, "DecimalWord", UnsignedIntegerDataType.dataType, dtm),
            null);
    var other =
        dtm.addDataType(
            new TypedefDataType(
                CategoryPath.ROOT, "OtherWord", UnsignedIntegerDataType.dataType, dtm),
            null);
    FormatSettingsDefinition.DEF.setChoice(
        word.getDefaultSettings(), FormatSettingsDefinition.DECIMAL);
    FormatSettingsDefinition.DEF.setChoice(
        other.getDefaultSettings(), FormatSettingsDefinition.DECIMAL);
    var structure = new StructureDataType("InheritedBits", 4, dtm);
    structure.insertBitFieldAt(0, 4, 0, word, 3, "inherited", null);
    structure.insertBitFieldAt(0, 4, 4, word, 3, "explicit", null);
    var saved = (Structure) dtm.addDataType(structure, null);
    FormatSettingsDefinition.DEF.setChoice(
        saved.getComponent(1).getDefaultSettings(), FormatSettingsDefinition.DECIMAL);
  }
}
