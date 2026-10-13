import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.symbol.SourceType;

public class CreateGuardedThunkDeletion extends GhidraScript {
  public void run() throws Exception {
    var manager = currentProgram.getFunctionManager();
    var target =
        manager.createFunction(
            "guarded_target",
            toAddr(0x1020),
            new AddressSet(toAddr(0x1020), toAddr(0x1020)),
            SourceType.USER_DEFINED);
    var thunk =
        manager.createFunction(
            null,
            toAddr(0x1030),
            new AddressSet(toAddr(0x1030), toAddr(0x103f)),
            SourceType.DEFAULT);
    thunk.setThunkedFunction(target);
    var indirect =
        manager.createFunction(
            null,
            toAddr(0x1040),
            new AddressSet(toAddr(0x1040), toAddr(0x1040)),
            SourceType.DEFAULT);
    indirect.setThunkedFunction(thunk);
    currentProgram
        .getSymbolTable()
        .createLabel(toAddr(0x1010), "guarded_target", SourceType.USER_DEFINED);
    currentProgram
        .getSymbolTable()
        .createLabel(toAddr(0x1031), "guarded_target", thunk, SourceType.USER_DEFINED);

    // Establish the native cascade independently of the CLI guards.
    var nativeTarget =
        manager.createFunction(
            "native_target",
            toAddr(0x1060),
            new AddressSet(toAddr(0x1060), toAddr(0x1060)),
            SourceType.USER_DEFINED);
    var nativeThunk =
        manager.createFunction(
            "native_thunk",
            toAddr(0x1070),
            new AddressSet(toAddr(0x1070), toAddr(0x1070)),
            SourceType.USER_DEFINED);
    nativeThunk.setThunkedFunction(nativeTarget);
    if (!manager.removeFunction(nativeTarget.getEntryPoint())
        || manager.getFunctionAt(toAddr(0x1070)) != null)
      throw new IllegalStateException("Native deletion must also delete the referring thunk");
  }
}
