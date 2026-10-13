import ghidra.app.script.GhidraScript;
import ghidra.docking.settings.FormatSettingsDefinition;
import ghidra.program.model.data.Structure;

public class SetAnchorFormat extends GhidraScript {
  public void run() throws Exception {
    var holder = (Structure) currentProgram.getDataTypeManager().getDataType("/Holder");
    FormatSettingsDefinition.DEF.setChoice(
        holder.getComponent(0).getDefaultSettings(), FormatSettingsDefinition.DECIMAL);
  }
}
