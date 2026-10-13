import ghidra.app.script.GhidraScript;

public class InspectStorageOffset extends GhidraScript {
  public void run() throws Exception {
    var storage = getFunctionAt(toAddr(0x1000)).getReturn().getVariableStorage();
    if (storage.getRegisterOffset(currentProgram.getRegister(getScriptArgs()[0])) != 0
        || storage.getRegisterOffset(currentProgram.getRegister(getScriptArgs()[1])) != 4)
      throw new IllegalStateException("Native byte order differs from requested value offsets");
  }
}
