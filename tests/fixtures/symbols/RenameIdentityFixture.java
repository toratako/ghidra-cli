import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.listing.LocalVariableImpl;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;

public class RenameIdentityFixture extends GhidraScript {
    public void run() throws Exception {
        var table = currentProgram.getSymbolTable();
        table.createLabel(toAddr(0x1010), "rename_selected", SourceType.USER_DEFINED);
        var function = currentProgram.getFunctionManager().createFunction("rename_owner", toAddr(0x1020),
            new AddressSet(toAddr(0x1020), toAddr(0x1020)), SourceType.USER_DEFINED);
        var parameter = function.addParameter(new ParameterImpl("rename_selected", IntegerDataType.dataType,
            currentProgram), SourceType.USER_DEFINED);

        // Establish the native coercion separately, without retaining its effects.
        parameter.setName("param_99", SourceType.USER_DEFINED);
        if (!parameter.getName().equals("param_1")) {
            throw new IllegalStateException("Fixture requires generated parameter name substitution");
        }
        parameter.setName("rename_selected", SourceType.USER_DEFINED);
        var generated = currentProgram.getFunctionManager().createFunction("generated_owner", toAddr(0x1040),
            new AddressSet(toAddr(0x1040), toAddr(0x1040)), SourceType.USER_DEFINED);
        generated.addParameter(new ParameterImpl(null, IntegerDataType.dataType, currentProgram),
            SourceType.DEFAULT);
        generated.addLocalVariable(new LocalVariableImpl(null, IntegerDataType.dataType, -4, currentProgram),
            SourceType.DEFAULT);
        table.createLabel(toAddr(0x1050), "param_1", SourceType.USER_DEFINED);
        currentProgram.getReferenceManager().addMemoryReference(toAddr(0x1000), toAddr(0x1030),
            RefType.DATA, SourceType.USER_DEFINED, 0);
        if (!table.getPrimarySymbol(toAddr(0x1030)).isDynamic()) {
            throw new IllegalStateException("Fixture requires a generated label");
        }
    }
}
