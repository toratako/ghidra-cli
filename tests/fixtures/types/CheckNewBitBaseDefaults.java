import ghidra.app.script.GhidraScript;
import ghidra.docking.settings.FormatSettingsDefinition;
import ghidra.program.model.data.Structure;

public class CheckNewBitBaseDefaults extends GhidraScript {
  public void run() throws Exception {
    var structure = (Structure) currentProgram.getDataTypeManager().getDataType("/InheritedBits");
    var inherited = structure.getComponent(0).getDefaultSettings();
    if (inherited.getNames().length != 0)
      throw new IllegalStateException("Old inherited default became explicit after base edit");
    if (FormatSettingsDefinition.DEF.getChoice(inherited) != FormatSettingsDefinition.DECIMAL)
      throw new IllegalStateException("Replacement base defaults were not inherited");
  }
}
