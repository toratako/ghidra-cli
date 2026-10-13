
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.symbol.SourceType;
public class ReownCallSite extends GhidraScript {
    public void run() throws Exception {
        getFunctionAt(toAddr(0x1000)).setBody(new AddressSet(toAddr(0x1000), toAddr(0x1004)));
        currentProgram.getFunctionManager().createFunction("new_owner", toAddr(0x1005),
            new AddressSet(toAddr(0x1005), toAddr(0x101a)), SourceType.USER_DEFINED);
    }
}
