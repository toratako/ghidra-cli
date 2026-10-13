import ghidra.app.script.GhidraScript;
import ghidra.docking.settings.FormatSettingsDefinition;
import ghidra.program.model.data.*;

public class CreateUnionSettings extends GhidraScript {
  public void run() throws Exception {
    var dtm = currentProgram.getDataTypeManager();
    for (boolean packed : new boolean[] {false, true}) {
      String name = packed ? "Packed" : "Unpacked";
      var union = new UnionDataType(CategoryPath.ROOT, name, dtm);
      union.setDescription("recovered layout");
      if (packed) {
        union.setExplicitPackingValue(2);
        union.setExplicitMinimumAlignment(16);
      }
      union.add(QWordDataType.dataType, "wide", "wide comment");
      union.add(DWordDataType.dataType, null, "unnamed comment");
      var registered = (Union) dtm.addDataType(union, null);
      for (var field : registered.getComponents()) {
        FormatSettingsDefinition.DEF.setChoice(
            field.getDefaultSettings(), FormatSettingsDefinition.DECIMAL);
        EndianSettingsDefinition.DEF.setChoice(
            field.getDefaultSettings(), EndianSettingsDefinition.BIG);
      }
      var holder = new StructureDataType(CategoryPath.ROOT, name + "Holder", 24, dtm);
      holder.replaceAtOffset(0, registered, registered.getLength(), "payload", "union field");
      holder.replaceAtOffset(16, DWordDataType.dataType, 4, "tail", "tail comment");
      var saved = (Structure) dtm.addDataType(holder, null);
      FormatSettingsDefinition.DEF.setChoice(
          saved.getComponentAt(16).getDefaultSettings(), FormatSettingsDefinition.BINARY);
    }
  }
}
