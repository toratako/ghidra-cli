import ghidra.app.script.GhidraScript;

public class ApplyMultiReplacement extends GhidraScript {
  public void run() throws Exception {
    var address = toAddr(0x1000);
    currentProgram
        .getMemory()
        .createInitializedBlock("data", address, 64, (byte) 0, monitor, false);
    currentProgram
        .getListing()
        .createData(address, currentProgram.getDataTypeManager().getDataType("/Wrapper"));
    currentProgram
        .getListing()
        .createData(
            address.add(32), currentProgram.getDataTypeManager().getDataType("/MorphHolder"));
    currentProgram
        .getListing()
        .createData(address.add(48), currentProgram.getDataTypeManager().getDataType("/Morph"));
  }
}
