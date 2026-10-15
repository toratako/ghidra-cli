import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.Undefined4DataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.ReturnParameterImpl;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.symbol.SourceType;

public class CreateBoundaryStackParameter extends GhidraScript {
  public void run() throws Exception {
    var address = toAddr(0x1000);
    currentProgram
        .getMemory()
        .createInitializedBlock("code", address, 1, (byte) 0xc3, monitor, false);
    var function =
        currentProgram
            .getFunctionManager()
            .createFunction("entry", address, new AddressSet(address), SourceType.USER_DEFINED);
    function.updateFunction(
        "__cdecl",
        new ReturnParameterImpl(VoidDataType.dataType, currentProgram),
        FunctionUpdateType.CUSTOM_STORAGE,
        false,
        SourceType.USER_DEFINED,
        new ParameterImpl(
            "value",
            Undefined4DataType.dataType,
            new VariableStorage(currentProgram, Integer.MAX_VALUE - 3, 4),
            currentProgram,
            SourceType.USER_DEFINED));
    if (!new DisassembleCommand(address, null, true).applyTo(currentProgram, monitor))
      throw new IllegalStateException("Fixture disassembly failed");
  }
}
