
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.symbol.SourceType;
public class CreateMemoryMappedStorageFunction extends GhidraScript {
    public void run() throws Exception {
        var address = toAddr(0x1000);
        currentProgram.getFunctionManager().createFunction("entry", address,
            new AddressSet(address), SourceType.USER_DEFINED);
        var register = currentProgram.getRegister("W0");
        if (!register.getAddress().isMemoryAddress())
            throw new IllegalStateException("Fixture requires a memory-mapped ABI register");
    }
}
