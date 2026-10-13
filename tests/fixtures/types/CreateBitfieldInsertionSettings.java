import ghidra.app.script.GhidraScript;
import ghidra.docking.settings.FormatSettingsDefinition;
import ghidra.program.model.data.*;

public class CreateBitfieldInsertionSettings extends GhidraScript {
  public void run() throws Exception {
    var dtm = currentProgram.getDataTypeManager();
    var child = new StructureDataType("GrowingBits", 4, dtm);
    child.replaceAtOffset(2, WordDataType.dataType, 2, "tail", "retained field");
    var saved = dtm.addDataType(child, null);
    var holder = new StructureDataType("BitSettingsHolder", 32, dtm);
    holder.replaceAtOffset(4, saved, 4, "first", null);
    holder.replaceAtOffset(16, saved, 4, "second", null);
    currentProgram
        .getMemory()
        .createInitializedBlock("data", toAddr(0x1000), 128, (byte) 0, monitor, false);
    var listing = currentProgram.getListing();
    var direct = listing.createData(toAddr(0x1000), saved);
    var savedHolder = (Structure) dtm.addDataType(holder, null);
    var nested = listing.createData(toAddr(0x1040), savedHolder);
    FormatSettingsDefinition.DEF.setChoice(
        direct.getComponent(2), FormatSettingsDefinition.DECIMAL);
    FormatSettingsDefinition.DEF.setChoice(
        nested.getComponent(savedHolder.getComponentAt(4).getOrdinal()).getComponent(2),
        FormatSettingsDefinition.BINARY);
    FormatSettingsDefinition.DEF.setChoice(
        nested.getComponent(savedHolder.getComponentAt(16).getOrdinal()).getComponent(2),
        FormatSettingsDefinition.OCTAL);
    var guarded = saved.copy(dtm);
    guarded.setName("GuardedBits");
    guarded = dtm.addDataType(guarded, null);
    var packed = new StructureDataType("GuardedBitHolder", 0, dtm);
    packed.setPackingEnabled(true);
    packed.add(guarded, "child", null);
    packed.add(ByteDataType.dataType, "tag", null);
    var guardedData = listing.createData(toAddr(0x1060), dtm.addDataType(packed, null));
    FormatSettingsDefinition.DEF.setChoice(
        guardedData.getComponent(1), FormatSettingsDefinition.BINARY);
  }
}
