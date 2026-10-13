
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.symbol.SourceType;
public class CreateNamespaceThunks extends GhidraScript {
    public void run() throws Exception {
        var manager = currentProgram.getFunctionManager();
        var target = getFunctionAt(toAddr(0x1050));
        var inside = manager.createFunction("inside_thunk", toAddr(0x1060),
            new AddressSet(toAddr(0x1060)), SourceType.USER_DEFINED);
        inside.setParentNamespace(target.getParentNamespace());
        inside.setThunkedFunction(target);
        var outside = manager.createFunction("outside_thunk", toAddr(0x1070),
            new AddressSet(toAddr(0x1070)), SourceType.USER_DEFINED);
        outside.setThunkedFunction(inside);
        var indirect = manager.createFunction("indirect_thunk", toAddr(0x1080),
            new AddressSet(toAddr(0x1080)), SourceType.USER_DEFINED);
        indirect.setThunkedFunction(outside);
    }
}
