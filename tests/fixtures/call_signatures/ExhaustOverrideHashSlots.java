import ghidra.app.script.GhidraScript;
import ghidra.app.util.parser.FunctionSignatureParser;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.pcode.DataTypeSymbol;
import ghidra.program.model.pcode.HighFunctionDBUtil;

/** Cause a real native writer failure after the previous marker was removed. */
public class ExhaustOverrideHashSlots extends GhidraScript {
    public void run() throws Exception {
        var manager = currentProgram.getDataTypeManager();
        var definition = new FunctionSignatureParser(manager, null)
            .parse(null, "char * replacement(int value)");
        definition.setName("tmpname");
        definition.setCallingConvention("__cdecl");
        int hash = DataTypeSymbol.generateHash(definition);
        var category = new CategoryPath(HighFunctionDBUtil.AUTO_CAT);
        for (int i = 0; i < 256; i++) {
            String name = "dt_" + Integer.toHexString(hash + i);
            if (manager.getDataType(category, name) != null) {
                throw new IllegalStateException("Collision fixture would overwrite an existing datatype");
            }
            manager.addDataType(new StructureDataType(category, name, 1, manager), null);
        }
    }
}
