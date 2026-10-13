
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.listing.LocalVariableImpl;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.symbol.*;
public class CreateAllSymbolKinds extends GhidraScript {
    public void run() throws Exception {
        var table = currentProgram.getSymbolTable();
        var namespace = table.createNameSpace(currentProgram.getGlobalNamespace(),
            "list_scope", SourceType.USER_DEFINED);
        table.createClass(namespace, "list_class", SourceType.USER_DEFINED);
        table.createLabel(toAddr(0x1010), "list_label", namespace, SourceType.USER_DEFINED);
        var entry = toAddr(0x1020);
        var function = currentProgram.getFunctionManager().createFunction("list_function", entry,
            new AddressSet(entry, entry), SourceType.USER_DEFINED);
        function.addParameter(new ParameterImpl("list_parameter", IntegerDataType.dataType,
            currentProgram), SourceType.USER_DEFINED);
        function.addLocalVariable(new LocalVariableImpl("list_local", IntegerDataType.dataType,
            -4, currentProgram), SourceType.USER_DEFINED);
        currentProgram.getExternalManager().addExtLocation("list_library", "list_external",
            null, SourceType.USER_DEFINED);
        currentProgram.getReferenceManager().addMemoryReference(toAddr(0x1000), toAddr(0x1030),
            RefType.DATA, SourceType.USER_DEFINED, 0);
        if (!table.getPrimarySymbol(toAddr(0x1030)).isDynamic())
            throw new IllegalStateException("Expected dynamic symbol");
    }
}
