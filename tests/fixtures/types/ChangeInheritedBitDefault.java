import ghidra.app.script.GhidraScript;
import ghidra.docking.settings.FormatSettingsDefinition;
import ghidra.program.model.data.Structure;

public class ChangeInheritedBitDefault extends GhidraScript {
  public void run() throws Exception {
    var dtm = currentProgram.getDataTypeManager();
    var structure = (Structure) dtm.getDataType("/InheritedBits");
    var inherited = structure.getComponent(0).getDefaultSettings();
    var explicit = structure.getComponent(1).getDefaultSettings();
    if (inherited.getNames().length != 0 || explicit.getNames().length == 0)
      throw new IllegalStateException("Changed explicit setting keys");
    FormatSettingsDefinition.DEF.setChoice(
        dtm.getDataType("/DecimalWord").getDefaultSettings(), FormatSettingsDefinition.HEX);
    if (FormatSettingsDefinition.DEF.getChoice(inherited) != FormatSettingsDefinition.HEX)
      throw new IllegalStateException("Lost inherited default after width edit");
    if (FormatSettingsDefinition.DEF.getChoice(explicit) != FormatSettingsDefinition.DECIMAL)
      throw new IllegalStateException("Lost explicit override after width edit");
  }
}
