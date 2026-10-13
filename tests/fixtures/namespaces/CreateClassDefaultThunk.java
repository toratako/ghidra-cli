
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.symbol.SourceType;
public class CreateClassDefaultThunk extends GhidraScript {
    public void run() throws Exception {
        var thunk = currentProgram.getFunctionManager().createFunction(null, toAddr(0x1060),
            new AddressSet(toAddr(0x1060)), SourceType.DEFAULT);
        thunk.setThunkedFunction(getFunctionAt(toAddr(0x1040)));
    }
}
