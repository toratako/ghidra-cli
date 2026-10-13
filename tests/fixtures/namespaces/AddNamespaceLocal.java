
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.listing.LocalVariableImpl;
import ghidra.program.model.symbol.SourceType;
public class AddNamespaceLocal extends GhidraScript {
    public void run() throws Exception {
        getFunctionAt(toAddr(0x1040)).addLocalVariable(new LocalVariableImpl("scratch",
            IntegerDataType.dataType, -4, currentProgram), SourceType.USER_DEFINED);
    }
}
