import ghidra.app.script.GhidraScript;
import ghidra.docking.settings.FormatSettingsDefinition;
import ghidra.program.model.data.*;

public class CreateFieldSettings extends GhidraScript {
  public void run() throws Exception {
    var dtm = currentProgram.getDataTypeManager();
    for (boolean packed : new boolean[] {false, true}) {
      String name = getScriptArgs()[0] + (packed ? "Packed" : "Unpacked");
      var structure = new StructureDataType(CategoryPath.ROOT, name, packed ? 0 : 24, dtm);
      if (packed) {
        structure.setPackingEnabled(true);
        structure.add(DWordDataType.dataType, "head", null);
        structure.add(DWordDataType.dataType, "tail", null);
      } else {
        structure.replaceAtOffset(0, DWordDataType.dataType, 4, "head", null);
        structure.replaceAtOffset(16, DWordDataType.dataType, 4, "tail", null);
      }
      var saved = (Structure) dtm.addDataType(structure, null);
      for (var component : saved.getDefinedComponents()) {
        FormatSettingsDefinition.DEF.setChoice(
            component.getDefaultSettings(), FormatSettingsDefinition.DECIMAL);
        EndianSettingsDefinition.DEF.setChoice(
            component.getDefaultSettings(), EndianSettingsDefinition.BIG);
      }
    }
  }
}
