import ghidra.app.script.GhidraScript;
import ghidra.docking.settings.FormatSettingsDefinition;
import ghidra.program.model.data.*;

public class CreateFieldDeletionSettingsCases extends GhidraScript {
  public void run() throws Exception {
    var dtm = currentProgram.getDataTypeManager();
    int address = 0x1000;
    for (boolean keepSettings : new boolean[] {true, false}) {
      String suffix = keepSettings ? "Guarded" : "Free";
      var union = new UnionDataType(CategoryPath.ROOT, "DeleteUnion" + suffix, dtm);
      union.add(QWordDataType.dataType, "wide", null);
      union.add(DWordDataType.dataType, "narrow", null);
      var savedUnion = dtm.addDataType(union, null);
      var holder = new StructureDataType("DeleteHolder" + suffix, 0, dtm);
      holder.setPackingEnabled(true);
      holder.add(savedUnion, "payload", null);
      holder.add(ByteDataType.dataType, "tail", null);
      var packed = new StructureDataType("DeleteStruct" + suffix, 0, dtm);
      packed.setPackingEnabled(true);
      packed.add(QWordDataType.dataType, "wide", null);
      packed.add(DWordDataType.dataType, "tail", null);
      for (var type : new StructureDataType[] {holder, packed}) {
        currentProgram
            .getMemory()
            .createInitializedBlock(type.getName(), toAddr(address), 32, (byte) 0, monitor, false);
        var data =
            currentProgram.getListing().createData(toAddr(address), dtm.addDataType(type, null));
        if (keepSettings)
          FormatSettingsDefinition.DEF.setChoice(
              data.getComponent(1), FormatSettingsDefinition.BINARY);
        address += 0x100;
      }
    }
  }
}
