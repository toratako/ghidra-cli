import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;

/** Deterministic x86 code and types, independent of the host compiler and ABI. */
public class CreateSemanticTypeUsesFixture extends GhidraScript {
    private ProgramDB program;

    private Address address(long offset) {
        return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
    }

    private Function function(String name, long offset, DataType parameter, int... bytes)
            throws Exception {
        byte[] code = new byte[bytes.length];
        for (int i = 0; i < bytes.length; i++) code[i] = (byte) bytes[i];
        Address entry = address(offset);
        AddressSet body = new AddressSet(entry, entry.add(bytes.length - 1));
        program.getMemory().setBytes(entry, code);
        if (!new DisassembleCommand(entry, body, true).applyTo(program, monitor)) {
            throw new IllegalStateException("Cannot disassemble " + name);
        }
        Function function = program.getFunctionManager().createFunction(name, entry, body,
            SourceType.USER_DEFINED);
        function.setCallingConvention("__cdecl");
        function.setReturnType(IntegerDataType.dataType, SourceType.USER_DEFINED);
        if (parameter != null) {
            function.addParameter(new ParameterImpl("ctx", parameter, program), SourceType.USER_DEFINED);
        }
        return function;
    }

    private DataType pointer(DataType type) {
        return new PointerDataType(type, 4, program.getDataTypeManager());
    }

    public void run() throws Exception {
        var language = DefaultLanguageService.getLanguageService()
            .getLanguage(new LanguageID("x86:LE:32:default"));
        program = new ProgramDB(getScriptArgs()[0], language,
            language.getDefaultCompilerSpec(), this);
        try {
            int transaction = program.startTransaction("semantic type uses fixture");
            try {
                var block = program.getMemory().createInitializedBlock("code", address(0x1000),
                    0x1000, (byte) 0, monitor, false);
                block.setExecute(true);
                var dtm = program.getDataTypeManager();
                var category = new CategoryPath("/Semantic");
                var definition = new StructureDataType(category, "Packet", 0, dtm);
                definition.add(IntegerDataType.dataType, "zero", null);
                definition.add(IntegerDataType.dataType, "count", null);
                definition.add(new ArrayDataType(IntegerDataType.dataType, 2, 4, dtm), "values", null);
                DataType packet = dtm.addDataType(definition, null);
                var otherDefinition = new StructureDataType(new CategoryPath("/Other"), "Packet", 20, dtm);
                otherDefinition.replaceAtOffset(8, IntegerDataType.dataType, 4, "count", null);
                DataType other = dtm.addDataType(otherDefinition, null);
                var twinDefinition = new StructureDataType(new CategoryPath("/Twin"), "Packet", 0, dtm);
                twinDefinition.add(IntegerDataType.dataType, "zero", null);
                twinDefinition.add(IntegerDataType.dataType, "count", null);
                twinDefinition.add(new ArrayDataType(IntegerDataType.dataType, 2, 4, dtm), "values", null);
                DataType twin = dtm.addDataType(twinDefinition, null);
                DataType alias = dtm.addDataType(new TypedefDataType(category, "PacketAlias", packet, dtm), null);
                DataType packets = dtm.addDataType(new ArrayDataType(alias, 2, -1, dtm), null);
                dtm.addDataType(new StructureDataType(category, "Unused", 4, dtm), null);

                function("read_count", 0x1000, pointer(packet),
                    0x8b, 0x44, 0x24, 0x04, 0x8b, 0x40, 0x04, 0xc3);
                function("write_count", 0x1040, pointer(packet),
                    0x8b, 0x44, 0x24, 0x04, 0xc7, 0x40, 0x04, 0x07, 0x00, 0x00, 0x00,
                    0x31, 0xc0, 0xc3);
                var addressCount = function("address_count", 0x1080, pointer(packet),
                    0x8b, 0x44, 0x24, 0x04, 0x83, 0xc0, 0x04, 0xc3);
                addressCount.setReturnType(pointer(IntegerDataType.dataType), SourceType.USER_DEFINED);
                function("update_count", 0x10c0, pointer(packet),
                    0x8b, 0x44, 0x24, 0x04, 0xff, 0x40, 0x04, 0x31, 0xc0, 0xc3);
                function("read_zero", 0x1100, pointer(packet),
                    0x8b, 0x44, 0x24, 0x04, 0x8b, 0x00, 0xc3);
                function("other_read", 0x1140, pointer(other),
                    0x8b, 0x44, 0x24, 0x04, 0x8b, 0x40, 0x08, 0xc3);
                function("alias_read", 0x1180, pointer(alias),
                    0x8b, 0x44, 0x24, 0x04, 0x8b, 0x40, 0x04, 0xc3);
                function("array_read", 0x11c0, pointer(packets),
                    0x8b, 0x44, 0x24, 0x04, 0x8b, 0x40, 0x14, 0xc3);
                function("by_value", 0x1200, packet,
                    0x8b, 0x44, 0x24, 0x08, 0x03, 0x44, 0x24, 0x04, 0xc3);
                var envelopeDefinition = new StructureDataType(category, "Envelope", 0, dtm);
                envelopeDefinition.add(IntegerDataType.dataType, "header", null);
                envelopeDefinition.add(packet, "packet", null);
                DataType envelope = dtm.addDataType(envelopeDefinition, null);
                function("nested_read", 0x1240, pointer(envelope),
                    0x8b, 0x44, 0x24, 0x04, 0x8b, 0x40, 0x08, 0xc3);
                function("read_values", 0x1280, pointer(packet),
                    0x8b, 0x44, 0x24, 0x04, 0x8b, 0x40, 0x0c, 0xc3);
                function("no_access", 0x12c0, pointer(packet), 0x31, 0xc0, 0xc3);
                function("inspect_packet", 0x1300, pointer(packet),
                    0x8b, 0x44, 0x24, 0x04, 0x8b, 0x40, 0x04, 0xc3);
                // inspect_packet(&local) infers Packet with no saved LocalVariable.
                function("inferred_local", 0x1340, null,
                    0x55, 0x89, 0xe5, 0x83, 0xec, 0x10,
                    0xc7, 0x45, 0xf0, 0x02, 0x00, 0x00, 0x00,
                    0xc7, 0x45, 0xf4, 0x03, 0x00, 0x00, 0x00,
                    0x8d, 0x45, 0xf0, 0x50, 0xe8, 0xa3, 0xff, 0xff, 0xff,
                    0x83, 0xc4, 0x04,
                    0x8d, 0x45, 0xf4, 0x50, 0xe8, 0x57, 0x01, 0x00, 0x00,
                    0x83, 0xc4, 0x04, 0xc9, 0xc3);
                // The argument type flows back from a typed callee into a DEFAULT signature.
                var inferred = function("inferred_parameter", 0x1380, null,
                    0x8b, 0x44, 0x24, 0x04, 0x50, 0xe8, 0x76, 0xff, 0xff, 0xff,
                    0x83, 0xc4, 0x04, 0xc3);
                inferred.setSignatureSource(SourceType.DEFAULT);
                function("twin_read", 0x13c0, pointer(twin),
                    0x8b, 0x44, 0x24, 0x04, 0x8b, 0x40, 0x04, 0xc3);
                var unionDefinition = new UnionDataType(category, "Choice", dtm);
                unionDefinition.add(IntegerDataType.dataType, "left", null);
                unionDefinition.add(IntegerDataType.dataType, "right", null);
                DataType choice = dtm.addDataType(unionDefinition, null);
                function("union_read", 0x1400, pointer(choice),
                    0x8b, 0x44, 0x24, 0x04, 0x8b, 0x00, 0xc3);
                var bitsDefinition = new StructureDataType(category, "Bits", 4, dtm);
                bitsDefinition.insertBitFieldAt(0, 4, 0, UnsignedIntegerDataType.dataType, 1, "low", null);
                bitsDefinition.insertBitFieldAt(0, 4, 1, UnsignedIntegerDataType.dataType, 1, "high", null);
                DataType bits = dtm.addDataType(bitsDefinition, null);
                function("bit_read", 0x1440, pointer(bits),
                    0x8b, 0x44, 0x24, 0x04, 0x0f, 0xb6, 0x00, 0x83, 0xe0, 0x01, 0xc3);
                function("address_to_call", 0x1480, pointer(packet),
                    0x8b, 0x44, 0x24, 0x04, 0x83, 0xc0, 0x04, 0x50,
                    0xe8, 0x33, 0x00, 0x00, 0x00, 0x83, 0xc4, 0x04, 0xc3);
                function("consume_int", 0x14c0, pointer(IntegerDataType.dataType), 0xc3);
                // A simple return can coalesce a field's HighVariable with EAX.
                // Moving its value must not become a write to the aggregate.
                function("by_value_return", 0x1540, packet,
                    0x8b, 0x44, 0x24, 0x08, 0xc3);
                function("bit_write", 0x1580, pointer(bits),
                    0x8b, 0x44, 0x24, 0x04, 0x80, 0x08, 0x01, 0x31, 0xc0, 0xc3);
                // An internal function with a body but no mapped instructions must
                // make an exhaustive semantic scan report a decompilation failure.
                var failed = program.getFunctionManager().createFunction("unmapped", address(0x3000),
                    new AddressSet(address(0x3000), address(0x3000)), SourceType.USER_DEFINED);
                failed.setReturnType(IntegerDataType.dataType, SourceType.USER_DEFINED);
                program.getExternalManager().addExtFunction("library", "external_packet", null,
                    SourceType.IMPORTED);
            } finally {
                program.endTransaction(transaction, true);
            }
            state.getProject().getProjectData().getRootFolder()
                .createFile(getScriptArgs()[0], program, monitor);
        } finally {
            program.release(this);
        }
    }
}
