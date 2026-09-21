import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.symbol.SourceType;

public class CreateStackPurgeFixture extends GhidraScript {
    private Function function(String name, long offset, int length) throws Exception {
        var address = toAddr(offset);
        if (getInstructionAt(address) == null && !disassemble(address))
            throw new IllegalStateException("Cannot disassemble " + name);
        return currentProgram.getFunctionManager().createFunction(name, address,
            new AddressSet(address, address.add(length - 1)), SourceType.USER_DEFINED);
    }

    public void run() throws Exception {
        currentProgram.getMemory().getBlock(toAddr(0x1000)).setExecute(true);
        Function caller = function("caller", 0x1000, 22);
        caller.setReturnType(IntegerDataType.dataType, SourceType.USER_DEFINED);
        caller.setCallingConvention("__cdecl");
        caller.setSignatureSource(SourceType.USER_DEFINED);

        Function callee = function("callee", 0x1100, 3);
        callee.updateFunction("__stdcall",
            new ghidra.program.model.listing.ReturnParameterImpl(VoidDataType.dataType, currentProgram),
            Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.USER_DEFINED,
            new ParameterImpl("value", IntegerDataType.dataType, currentProgram));
        callee.setStackPurgeSize(Function.UNKNOWN_STACK_DEPTH_CHANGE);

        Function invalid = function("invalid_purge", 0x1120, 1);
        invalid.setStackPurgeSize(Function.INVALID_STACK_DEPTH_CHANGE);
        Function thunk = function("callee_thunk", 0x1140, 5);
        thunk.setThunkedFunction(callee);
    }
}
