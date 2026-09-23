import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;

/** Native indirect calls with deliberately independent table/type/offset evidence. */
public class CreateVirtualCallersFixture extends GhidraScript {
    private ProgramDB program;
    private boolean arm;

    private Address address(long offset) {
        return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
    }

    private DataType pointer(DataType type) {
        return new PointerDataType(type, 8, program.getDataTypeManager());
    }

    private Function function(String name, long offset, DataType parameter, int... units)
            throws Exception {
        byte[] bytes = new byte[units.length * (arm ? 4 : 1)];
        for (int i = 0; i < units.length; i++) {
            for (int b = 0; b < (arm ? 4 : 1); b++) bytes[i * (arm ? 4 : 1) + b] = (byte) (units[i] >>> (8 * b));
        }
        Address entry = address(offset);
        AddressSet body = new AddressSet(entry, entry.add(bytes.length - 1));
        program.getMemory().setBytes(entry, bytes);
        if (!new DisassembleCommand(entry, body, true).applyTo(program, monitor)) {
            throw new IllegalStateException("Cannot disassemble " + name);
        }
        Function result = program.getFunctionManager().createFunction(name, entry, body,
            SourceType.USER_DEFINED);
        if (!arm) result.setCallingConvention("__cdecl");
        result.setReturnType(IntegerDataType.dataType, SourceType.USER_DEFINED);
        if (parameter != null) {
            result.addParameter(new ParameterImpl("object", parameter, program), SourceType.USER_DEFINED);
        }
        return result;
    }

    private DataType table(String category) throws Exception {
        var manager = program.getDataTypeManager();
        var prototype = new FunctionDefinitionDataType(new CategoryPath(category), "VirtualMethod", manager);
        prototype.setReturnType(IntegerDataType.dataType);
        var method = manager.addDataType(prototype, null);
        var definition = new StructureDataType(new CategoryPath(category), "Table", 0, manager);
        for (int i = 0; i < 4; i++) definition.add(pointer(method), "method" + i, null);
        return manager.addDataType(definition, null);
    }

    private DataType object(String name, DataType table) throws Exception {
        var definition = new StructureDataType(new CategoryPath("/Virtual"), name, 0,
            program.getDataTypeManager());
        definition.add(pointer(table), "vptr", null);
        return program.getDataTypeManager().addDataType(definition, null);
    }

    private void pointer(long offset, long value) throws Exception {
        program.getMemory().setLong(address(offset), value);
    }

    private void x86(DataType object, DataType twin) throws Exception {
        var target = function("virtual_target", 0x1000, null, 0xb8, 42, 0, 0, 0, 0xc3);
        function("other_target", 0x1040, null, 0xb8, 9, 0, 0, 0, 0xc3);
        var thunk = function("virtual_thunk", 0x1080, null, 0xe9, 0x7b, 0xff, 0xff, 0xff);
        thunk.setThunkedFunction(target);
        // mov eax, address_point; call [rax + slot]; ret.
        function("known_zero", 0x1100, null, 0xb8, 0x20, 0x30, 0, 0, 0xff, 0x10, 0xc3);
        function("known_nonzero", 0x1140, null, 0xb8, 0x20, 0x30, 0, 0, 0xff, 0x50, 8, 0xc3);
        function("known_thunk", 0x1180, null, 0xb8, 0x20, 0x30, 0, 0, 0xff, 0x50, 16, 0xc3);
        function("unrelated_table", 0x11c0, null, 0xb8, 0x60, 0x30, 0, 0, 0xff, 0x50, 8, 0xc3);
        // mov rax,[rdi]; call [rax + slot]; ret. The same bytes carry different types.
        function("unknown_zero", 0x1200, pointer(VoidDataType.dataType),
            0x48, 0x8b, 0x07, 0xff, 0x10, 0xc3);
        function("unknown_nonzero", 0x1240, pointer(VoidDataType.dataType),
            0x48, 0x8b, 0x07, 0xff, 0x50, 8, 0xc3);
        function("typed_zero", 0x1280, pointer(object), 0x48, 0x8b, 0x07, 0xff, 0x10, 0xc3);
        function("typed_nonzero", 0x12c0, pointer(object), 0x48, 0x8b, 0x07, 0xff, 0x50, 8, 0xc3);
        function("twin_type", 0x1300, pointer(twin), 0x48, 0x8b, 0x07, 0xff, 0x50, 8, 0xc3);
        // A phi joining a known table with an unknown vptr must not prove identity.
        function("mixed_phi", 0x1340, pointer(VoidDataType.dataType),
            0xb8, 0x20, 0x30, 0, 0, 0x85, 0xf6, 0x75, 3, 0x48, 0x8b, 0x07,
            0xff, 0x50, 8, 0xc3);
        function("unmatched_offset", 0x1380, pointer(VoidDataType.dataType),
            0x48, 0x8b, 0x07, 0xff, 0x50, 24, 0xc3);
        function("ordinary_direct_call", 0x13c0, null, 0xe8, 0x3b, 0xfc, 0xff, 0xff, 0xc3);
        function("two_calls", 0x1400, pointer(object),
            0x53, 0x48, 0x89, 0xfb, 0x48, 0x8b, 0x03, 0xff, 0x10,
            0x48, 0x8b, 0x03, 0xff, 0x50, 8, 0x5b, 0xc3);
        // LOAD target into a register in an earlier instruction, then CALLIND.
        function("split_load", 0x1440, pointer(object),
            0x48, 0x8b, 0x07, 0x48, 0x8b, 0x40, 8, 0xff, 0xd0, 0xc3);
        // Runtime slot selection cannot identify any one of the requested offsets.
        function("dynamic_slot", 0x1480, pointer(object),
            0x48, 0x8b, 0x07, 0xff, 0x14, 0xf0, 0xc3);
        // A callback parameter has no evidence of a vtable slot at all.
        function("ordinary_callback", 0x14c0, pointer(VoidDataType.dataType), 0xff, 0xd7, 0xc3);
    }

    private void aarch64(DataType object, DataType twin) throws Exception {
        var target = function("virtual_target", 0x1000, null, 0x52800540, 0xd65f03c0);
        function("other_target", 0x1040, null, 0x52800120, 0xd65f03c0);
        var thunk = function("virtual_thunk", 0x1080, null, 0x17ffffe0);
        thunk.setThunkedFunction(target);
        // stp x29,x30,[sp,#-16]!; mov x8,AP; ldr x8,[x8,#slot]; blr x8;
        // ldp x29,x30,[sp],#16; ret. LOAD and BLR necessarily have different sites.
        function("known_zero", 0x1100, null,
            0xa9bf7bfd, 0xd2860408, 0xf9400108, 0xd63f0100, 0xa8c17bfd, 0xd65f03c0);
        function("known_nonzero", 0x1140, null,
            0xa9bf7bfd, 0xd2860408, 0xf9400508, 0xd63f0100, 0xa8c17bfd, 0xd65f03c0);
        function("known_thunk", 0x1180, null,
            0xa9bf7bfd, 0xd2860408, 0xf9400908, 0xd63f0100, 0xa8c17bfd, 0xd65f03c0);
        function("unrelated_table", 0x11c0, null,
            0xa9bf7bfd, 0xd2860c08, 0xf9400508, 0xd63f0100, 0xa8c17bfd, 0xd65f03c0);
        for (int i = 0; i < 5; i++) {
            String[] names = {"unknown_zero", "unknown_nonzero", "typed_zero", "typed_nonzero", "twin_type"};
            DataType parameter = i < 2 ? pointer(VoidDataType.dataType) : pointer(i == 4 ? twin : object);
            function(names[i], 0x1200 + 0x40 * i, parameter, 0xa9bf7bfd, 0xf9400008,
                i == 0 || i == 2 ? 0xf9400108 : 0xf9400508,
                0xd63f0100, 0xa8c17bfd, 0xd65f03c0);
        }
        function("mixed_phi", 0x1340, pointer(VoidDataType.dataType),
            0xa9bf7bfd, 0xd2860408, 0xb5000041, 0xf9400008,
            0xf9400508, 0xd63f0100, 0xa8c17bfd, 0xd65f03c0);
        function("unmatched_offset", 0x1380, pointer(VoidDataType.dataType),
            0xa9bf7bfd, 0xf9400008, 0xf9400d08, 0xd63f0100, 0xa8c17bfd, 0xd65f03c0);
        function("ordinary_direct_call", 0x13c0, null,
            0xa9bf7bfd, 0x97ffff0f, 0xa8c17bfd, 0xd65f03c0);
    }

    public void run() throws Exception {
        String[] args = getScriptArgs();
        arm = args[1].startsWith("AARCH64");
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(args[1]));
        program = new ProgramDB(args[0], language, arm ? language.getDefaultCompilerSpec()
            : language.getCompilerSpecByID(new CompilerSpecID("gcc")), this);
        try {
            int transaction = program.startTransaction("virtual caller fixture");
            try {
                var memory = program.getMemory();
                memory.createInitializedBlock("zero_entry", address(0), 16, (byte) 0, monitor, false)
                    .setExecute(true);
                memory.createInitializedBlock("code", address(0x1000), 0x800, (byte) 0, monitor, false)
                    .setExecute(true);
                // Writable tables keep native decompilation from folding current bytes into direct calls.
                memory.createInitializedBlock("tables", address(0x3000), 0x100, (byte) 0, monitor, false)
                    .setWrite(true);
                DataType table = table("/Virtual");
                DataType twinTable = table("/Twin");
                DataType object = object("Object", table);
                DataType twinObject = object("TwinObject", twinTable);
                if (arm) aarch64(object, twinObject); else x86(object, twinObject);
                if (arm) function("zero_target", 0, null, 0x52800560, 0xd65f03c0);
                else function("zero_target", 0, null, 0xb8, 43, 0, 0, 0, 0xc3);
                long[] targets = {0x1000, 0x1000, 0x1080, 0x1040};
                for (int i = 0; i < targets.length; i++) {
                    pointer(0x3020 + 8 * i, targets[i]);
                    pointer(0x3060 + 8 * i, 0x1040);
                }
                pointer(0x30f8, 0x1000); // One readable slot followed by unmapped memory.
                pointer(0x30a0, 0x1001); // An interior address does not equal a callable entry.
                pointer(0x30a8, 0);
                pointer(0x30b0, 0x6000);
                program.getListing().createData(address(0x3020), table);
                // Same registered type does not override a proven different table address.
                program.getListing().createData(address(0x3060), table);
                program.getSymbolTable().createLabel(address(0x3020), "virtual_address_point", SourceType.USER_DEFINED);
                program.getSymbolTable().createLabel(address(0x3060), "other_address_point", SourceType.USER_DEFINED);
                // An internal body without mapped instructions must make an all-functions scan incomplete.
                program.getFunctionManager().createFunction("unmapped", address(0x5000),
                    new AddressSet(address(0x5000)), SourceType.USER_DEFINED);
                program.getExternalManager().addExtFunction("library", "external_target", null, SourceType.IMPORTED);
            } finally {
                program.endTransaction(transaction, true);
            }
            state.getProject().getProjectData().getRootFolder().createFile(args[0], program, monitor);
        } finally {
            program.release(this);
        }
    }
}
