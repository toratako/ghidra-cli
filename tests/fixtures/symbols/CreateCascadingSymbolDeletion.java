
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.symbol.*;
public class CreateCascadingSymbolDeletion extends GhidraScript {
    public void run() throws Exception {
        var table = currentProgram.getSymbolTable();
        var parent = currentProgram.getFunctionManager().createFunction(getScriptArgs()[0],
            toAddr("1000"), new AddressSet(toAddr("1000"), toAddr("101f")),
            SourceType.USER_DEFINED);
        table.createLabel(toAddr("1010"), getScriptArgs()[0], parent, SourceType.USER_DEFINED);
        var other = table.createNameSpace(currentProgram.getGlobalNamespace(),
            "unaffected", SourceType.USER_DEFINED);
        table.createLabel(toAddr("1020"), getScriptArgs()[0], other, SourceType.USER_DEFINED);
    }
}
