
import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.SourceType;
public class RenameExplicitObjectParameter extends GhidraScript {
    public void run() throws Exception {
        getFunctionAt(toAddr(0x1100)).getParameter(0).setName("object", SourceType.USER_DEFINED);
    }
}
