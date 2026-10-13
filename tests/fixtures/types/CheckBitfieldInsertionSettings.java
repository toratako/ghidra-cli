import ghidra.app.script.GhidraScript;
import ghidra.docking.settings.FormatSettingsDefinition;
import ghidra.program.model.data.Structure;

public class CheckBitfieldInsertionSettings extends GhidraScript {
  public void run() throws Exception {
    var type = (Structure) currentProgram.getDataTypeManager().getDataType("/GrowingBits");
    var holder = (Structure) currentProgram.getDataTypeManager().getDataType("/BitSettingsHolder");
    var tail = type.getDefinedComponents()[1];
    var direct = currentProgram.getListing().getDefinedDataAt(toAddr(0x1000));
    var nested = currentProgram.getListing().getDefinedDataAt(toAddr(0x1040));
    if (type.getLength() != 8
        || direct.getLength() != 8
        || nested.getLength() != 32
        || tail.getOffset() != 2
        || tail.getLength() != 2
        || holder.getComponentAt(4).getLength() != 8
        || holder.getComponentAt(16).getLength() != 8)
      throw new IllegalStateException("Incomplete bitfield insertion layout");
    if (FormatSettingsDefinition.DEF.getChoice(direct.getComponent(tail.getOrdinal()))
            != FormatSettingsDefinition.DECIMAL
        || FormatSettingsDefinition.DEF.getChoice(
                nested
                    .getComponent(holder.getComponentAt(4).getOrdinal())
                    .getComponent(tail.getOrdinal()))
            != FormatSettingsDefinition.BINARY
        || FormatSettingsDefinition.DEF.getChoice(
                nested
                    .getComponent(holder.getComponentAt(16).getOrdinal())
                    .getComponent(tail.getOrdinal()))
            != FormatSettingsDefinition.OCTAL)
      throw new IllegalStateException("Insertion changed retained applied settings");
    var guarded = currentProgram.getListing().getDefinedDataAt(toAddr(0x1060));
    if (guarded.getLength() != 5
        || guarded.getComponent(1).getMinAddress().getOffset() != 0x1064
        || FormatSettingsDefinition.DEF.getChoice(guarded.getComponent(1))
            != FormatSettingsDefinition.BINARY)
      throw new IllegalStateException("Rejected insertion moved a packed field or its settings");
  }
}
