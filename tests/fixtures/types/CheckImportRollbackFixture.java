import ghidra.app.script.GhidraScript;
import ghidra.docking.settings.FormatSettingsDefinition;
import ghidra.program.model.data.EndianSettingsDefinition;
import ghidra.program.model.data.Structure;

public class CheckImportRollbackFixture extends GhidraScript {
  public void run() throws Exception {
    var structure = (Structure) currentProgram.getDataTypeManager().getDataType("/Existing");
    if (structure.getLength() != 8 || structure.getNumComponents() != 2)
      throw new IllegalStateException("Existing structure layout changed");
    var component = structure.getComponent(0);
    if (!"value".equals(component.getFieldName())
        || !"tail".equals(structure.getComponent(1).getFieldName())
        || !"saved field comment".equals(component.getComment()))
      throw new IllegalStateException("Existing structure metadata changed");
    if (FormatSettingsDefinition.DEF.getChoice(component.getDefaultSettings())
            != FormatSettingsDefinition.DECIMAL
        || EndianSettingsDefinition.DEF.getChoice(component.getDefaultSettings())
            != EndianSettingsDefinition.BIG)
      throw new IllegalStateException("Existing field settings changed");
    var data = currentProgram.getListing().getDefinedDataAt(toAddr(0x1000));
    if (data == null
        || data.getLength() != 8
        || !data.getDataType().equals(structure)
        || !"value".equals(data.getComponent(0).getFieldName()))
      throw new IllegalStateException("Applied structure data changed");
    if (FormatSettingsDefinition.DEF.getChoice(data.getComponent(0))
            != FormatSettingsDefinition.BINARY
        || EndianSettingsDefinition.DEF.getChoice(data.getComponent(0))
            != EndianSettingsDefinition.LITTLE)
      throw new IllegalStateException("Applied field settings changed");
  }
}
