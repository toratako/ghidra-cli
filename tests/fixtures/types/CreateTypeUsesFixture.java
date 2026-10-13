import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.*;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;

public class CreateTypeUsesFixture extends GhidraScript {
    private ProgramDB program;

    private Function function(String name, long offset) throws Exception {
        var address = program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
        return program.getFunctionManager().createFunction(name, address,
            new AddressSet(address, address), SourceType.USER_DEFINED);
    }

    private void data(long offset, String name, DataType type) throws Exception {
        var address = program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
        program.getListing().createData(address, type);
        program.getSymbolTable().createLabel(address, name, SourceType.USER_DEFINED);
    }

    public void run() throws Exception {
        var language = DefaultLanguageService.getLanguageService()
            .getLanguage(new LanguageID("x86:LE:32:default"));
        program = new ProgramDB(getScriptArgs()[0], language,
            language.getCompilerSpecByID(new CompilerSpecID(getScriptArgs()[1])), this);
        try {
            int tx = program.startTransaction("type uses fixture");
            try {
                var dtm = program.getDataTypeManager();
                var path = new CategoryPath("/Recovered");
                var widget = dtm.addDataType(new StructureDataType(path, "Widget", 16), null);
                var other = dtm.addDataType(new StructureDataType(new CategoryPath("/Other"), "Widget", 16), null);
                dtm.addDataType(new StructureDataType(path, "Unused", 16), null);
                var alias = dtm.addDataType(new TypedefDataType(path, "WidgetAlias", widget), null);
                var pointer = dtm.addDataType(new PointerDataType(widget, dtm), null);
                var handle = dtm.addDataType(new TypedefDataType(path, "WidgetHandle", pointer), null);
                var pointerAlias = dtm.addDataType(new PointerDataType(alias, dtm), null);
                var container = new StructureDataType(path, "Container", 0);
                container.add(widget, "nested", null);
                var array = new ArrayDataType(widget, 3, -1, dtm);
                var nestedArray = new ArrayDataType(new ArrayDataType(handle, 3, -1, dtm), 2, -1, dtm);

                var start = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x2000);
                program.getMemory().createInitializedBlock("data", start, 0x1000, (byte) 0, monitor, false);
                data(0x2000, "direct", widget);
                data(0x2020, "pointer", pointer);
                data(0x2040, "array", array);
                data(0x2080, "alias", alias);
                data(0x20a0, "pointer_alias", pointerAlias);
                data(0x20c0, "nested_array", nestedArray);
                data(0x2100, "other", other);
                data(0x2120, "container", container);
                data(0x2140, "builtin", IntegerDataType.dataType);
                // Same name and byte length as a primitive, but a different registered type.
                data(0x2150, "named_int", new StructureDataType(path, "int", 4));

                // No instructions: database signature queries must not depend on decompilation.
                var process = function("process", 0x1000);
                process.updateFunction("__cdecl", new ReturnParameterImpl(pointer, program),
                    FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS, false, SourceType.USER_DEFINED,
                    new ParameterImpl("ctx", pointerAlias, program),
                    new ParameterImpl("other", new PointerDataType(other, dtm), program));
                var thunk = function("process_thunk", 0x1100);
                thunk.setThunkedFunction(process);
                function("chained_thunk", 0x1200).setThunkedFunction(thunk);

                var indirect = function("indirect", 0x1300);
                indirect.updateFunction("__cdecl", new ReturnParameterImpl(widget, program),
                    FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS, false, SourceType.IMPORTED,
                    new ParameterImpl("value", IntegerDataType.dataType, program));
                var local = function("local_only", 0x1400);
                local.addLocalVariable(new LocalVariableImpl("local", pointer, -8, program), SourceType.USER_DEFINED);

                var methodClass = program.getSymbolTable().createClass(null, "Widget", SourceType.USER_DEFINED);
                var wrapperClass = program.getSymbolTable().createClass(null, "Wrapper", SourceType.USER_DEFINED);
                dtm.addDataType(new StructureDataType("Widget", 8), null);
                dtm.addDataType(new StructureDataType("Wrapper", 8), null);
                var method = function("method", 0x1500);
                method.setParentNamespace(methodClass);
                method.updateFunction("__thiscall", new ReturnParameterImpl(VoidDataType.dataType, program),
                    FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS, false, SourceType.USER_DEFINED);
                var methodThunk = function("method_thunk", 0x1600);
                methodThunk.setParentNamespace(wrapperClass);
                methodThunk.setThunkedFunction(method);

                // Creation order is intentionally different from name order.
                for (String name : new String[] {"zeta", "alpha"}) {
                    var external = program.getExternalManager()
                        .addExtFunction("library", name, null, SourceType.IMPORTED).getFunction();
                    external.updateFunction("__cdecl", new ReturnParameterImpl(pointer, program),
                        FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS, false, SourceType.IMPORTED,
                        new ParameterImpl("ctx", pointer, program));
                }
            } finally {
                program.endTransaction(tx, true);
            }
            state.getProject().getProjectData().getRootFolder()
                .createFile(getScriptArgs()[0], program, monitor);
        } finally {
            program.release(this);
        }
    }
}
