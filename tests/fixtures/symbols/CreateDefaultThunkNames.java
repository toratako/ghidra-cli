
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.symbol.SourceType;
public class CreateDefaultThunkNames extends GhidraScript {
    public void run() throws Exception {
        var manager = currentProgram.getFunctionManager();
        var targetAddress = toAddr(0x1020);
        var target = manager.createFunction("default_target", targetAddress,
            new AddressSet(targetAddress, targetAddress), SourceType.USER_DEFINED);
        for (long offset : new long[] {0x1030, 0x1040}) {
            var address = toAddr(offset);
            var thunk = manager.createFunction(null, address,
                new AddressSet(address, address), SourceType.DEFAULT);
            thunk.setThunkedFunction(target);
        }
    }
}
