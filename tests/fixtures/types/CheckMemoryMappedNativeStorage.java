import ghidra.app.script.GhidraScript;

public class CheckMemoryMappedNativeStorage extends GhidraScript {
  public void run() throws Exception {
    var function = getFunctionAt(toAddr(0x1000));
    if (!function.getReturn().getVariableStorage().getRegisters().stream()
            .map(register -> register.getName())
            .toList()
            .equals(java.util.List.of("W1", "W0"))
        || !function.getParameter(0).getVariableStorage().isRegisterStorage()
        || !function.getParameter(1).getVariableStorage().getRegisters().stream()
            .map(register -> register.getName())
            .toList()
            .equals(java.util.List.of("W3", "W2")))
      throw new IllegalStateException("Native storage did not retain the ABI registers");
  }
}
