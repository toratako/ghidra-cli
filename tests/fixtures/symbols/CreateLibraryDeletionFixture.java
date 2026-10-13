
import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.SourceType;
public class CreateLibraryDeletionFixture extends GhidraScript {
    public void run() throws Exception {
        var table = currentProgram.getSymbolTable();
        var name = getScriptArgs()[0];
        table.createLabel(toAddr(0x1010), name, SourceType.USER_DEFINED);
        currentProgram.getExternalManager().addExtLocation(name, "owned_import_one",
            null, SourceType.USER_DEFINED);
        currentProgram.getExternalManager().addExtLocation(name, "owned_import_two",
            null, SourceType.USER_DEFINED);
        currentProgram.getExternalManager().addExternalLibraryName("empty_library",
            SourceType.USER_DEFINED);
    }
}
