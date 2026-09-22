import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.*;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class CreateDataFixture extends GhidraScript {
    public void run() throws Exception {
        var types = currentProgram.getDataTypeManager();
        var memory = currentProgram.getMemory();
        var inner = new StructureDataType("DataInner", 0, types);
        inner.add(new TypedefDataType("ExactUnsigned", UnsignedLongLongDataType.dataType),
            "large", null);
        inner.add(IntegerDataType.dataType, "negative", null);
        var overlay = new UnionDataType(CategoryPath.ROOT, "DataOverlay", types);
        overlay.add(UnsignedIntegerDataType.dataType, "number", null);
        overlay.add(new ArrayDataType(ByteDataType.dataType, 4, 1), "bytes", null);
        var record = new StructureDataType("DataRecord", 0, types);
        record.add(inner, "inner", null);
        record.add(new ArrayDataType(UnsignedShortDataType.dataType, 3, 2), "values", null);
        record.add(new PointerDataType(record, 8, types), "next", null);
        record.add(new ArrayDataType(CharDataType.dataType, 6, 1), "text", null);
        record.add(overlay, "interpretations", null);
        var buffer = ByteBuffer.allocate(36).order(ByteOrder.LITTLE_ENDIAN);
        buffer.putLong(-1L).putInt(-7).putShort((short) 0x1234).putShort((short) 0)
            .putShort((short) 0xffff).putLong(0x1000)
            .put(new byte[] {'h', 'e', 'l', 'l', 'o', 0}).putInt(0x12345678);
        memory.setBytes(toAddr(0x1000), buffer.array());
        createData(toAddr(0x1000), record);
        createLabel(toAddr(0x1000), "data_record", true, SourceType.USER_DEFINED);

        createData(toAddr(0x1100), UnsignedLongLongDataType.dataType);
        createLabel(toAddr(0x1100), "data_zero", true, SourceType.USER_DEFINED);
        memory.setLong(toAddr(0x1110), Long.MIN_VALUE);
        createData(toAddr(0x1110), LongLongDataType.dataType);
        memory.setLong(toAddr(0x1180), Double.doubleToRawLongBits(-1.25));
        createData(toAddr(0x1180), DoubleDataType.dataType);

        var enumType = new EnumDataType("DataUnsignedEnum", 1);
        enumType.add("ALL", 255);
        memory.setByte(toAddr(0x1190), (byte) 0xff);
        createData(toAddr(0x1190), enumType);
        memory.setBytes(toAddr(0x1194), new byte[] {0x12, 0x34});
        var endian = createData(toAddr(0x1194), UnsignedShortDataType.dataType);
        EndianSettingsDefinition.DEF.setChoice(endian, EndianSettingsDefinition.BIG);
        createData(toAddr(0x11a0), new PointerDataType(null, 8, types));

        var oddUnsigned = new EnumDataType("DataUnsignedEnum24", 3);
        oddUnsigned.add("WIDE", 0xffabcd);
        memory.setBytes(toAddr(0x1198), new byte[] {(byte) 0xcd, (byte) 0xab, (byte) 0xff});
        createData(toAddr(0x1198), oddUnsigned);
        var oddSigned = new EnumDataType("DataSignedEnum24", 3);
        oddSigned.add("NEGATIVE", -7);
        memory.setBytes(toAddr(0x11b0), new byte[] {(byte) 0xf9, (byte) 0xff, (byte) 0xff});
        createData(toAddr(0x11b0), oddSigned);

        var bits = new StructureDataType("DataBits", 1, types);
        bits.insertBitFieldAt(0, 1, 0, UnsignedCharDataType.dataType, 3, "low", null);
        bits.insertBitFieldAt(0, 1, 3, UnsignedCharDataType.dataType, 5, "high", null);
        memory.setByte(toAddr(0x1200), (byte) 0x8d);
        createData(toAddr(0x1200), bits);

        createData(toAddr(0x1300), new ArrayDataType(UnsignedShortDataType.dataType, 512, 2));
        memory.setShort(toAddr(0x1620), (short) 4242);
        createLabel(toAddr(0x1300), "data_large_array", true, SourceType.USER_DEFINED);

        memory.createUninitializedBlock("data_uninitialized", toAddr(0x4000), 32, false);
        createData(toAddr(0x4000), UnsignedLongLongDataType.dataType);
        createLabel(toAddr(0x4000), "data_uninitialized", true, SourceType.USER_DEFINED);

        memory.createInitializedBlock("partial_start", toAddr(0x5000), 4, (byte) 1,
            monitor, false);
        memory.createUninitializedBlock("partial_tail", toAddr(0x5004), 4, false);
        memory.createInitializedBlock("partial_sibling", toAddr(0x5008), 8, (byte) 0,
            monitor, false);
        var partial = new StructureDataType("PartialData", 0, types);
        partial.add(UnsignedLongLongDataType.dataType, "partial", null);
        partial.add(UnsignedLongLongDataType.dataType, "available", null);
        createData(toAddr(0x5000), partial);

        byte[] wide = new byte[16];
        java.util.Arrays.fill(wide, (byte) 0xff);
        memory.setBytes(toAddr(0x1800), wide);
        createData(toAddr(0x1800), UnsignedInteger16DataType.dataType);

        memory.createInitializedBlock("data_long_string", toAddr(0x10000), 65537,
            (byte) 'a', monitor, false);
        createData(toAddr(0x10000), new ArrayDataType(CharDataType.dataType, 65537, 1));

        createReferenceFixtures();
    }

    private void createReferenceFixtures() throws Exception {
        var memory = currentProgram.getMemory();
        var references = currentProgram.getReferenceManager();
        var record = new StructureDataType("ReferencedRecord", 0);
        record.add(UnsignedIntegerDataType.dataType, "header", null);
        record.add(new ArrayDataType(UnsignedIntegerDataType.dataType, 3, 4), "values", null);
        createData(toAddr(0x2000), record);
        createLabel(toAddr(0x2000), "references_record", true, SourceType.USER_DEFINED);
        createData(toAddr(0x2010), UnsignedIntegerDataType.dataType);
        createLabel(toAddr(0x2010), "references_adjacent", true, SourceType.USER_DEFINED);
        createData(toAddr(0x2100), new ArrayDataType(UnsignedIntegerDataType.dataType, 64, 4));
        createLabel(toAddr(0x2100), "references_array", true, SourceType.USER_DEFINED);
        createData(toAddr(0x2200), UnsignedIntegerDataType.dataType);
        createLabel(toAddr(0x2200), "references_none", true, SourceType.USER_DEFINED);

        // Two operands of one instruction referencing the same destination count separately.
        memory.setBytes(toAddr(0x2900), new byte[] {(byte) 0x89, 0x00}); // MOV [RAX], EAX
        if (!new DisassembleCommand(toAddr(0x2900),
                new AddressSet(toAddr(0x2900), toAddr(0x2901)), false)
                .applyTo(currentProgram, monitor)) {
            throw new IllegalStateException("Could not disassemble data reference fixture");
        }
        references.addMemoryReference(toAddr(0x2900), toAddr(0x2000), RefType.WRITE,
            SourceType.USER_DEFINED, 0);
        references.addMemoryReference(toAddr(0x2900), toAddr(0x2000), RefType.READ,
            SourceType.USER_DEFINED, 1);
        references.addMemoryReference(toAddr(0x2910), toAddr(0x2004), RefType.DATA,
            SourceType.USER_DEFINED, 0);
        references.addMemoryReference(toAddr(0x2920), toAddr(0x200f), RefType.READ,
            SourceType.USER_DEFINED, 0);
        references.addMemoryReference(toAddr(0x2008), toAddr(0x200c), RefType.DATA,
            SourceType.USER_DEFINED, 0); // An internal reference is still incoming to the object.
        references.addMemoryReference(toAddr(0x2930), toAddr(0x2010), RefType.DATA,
            SourceType.USER_DEFINED, 0);
        references.addMemoryReference(toAddr(0x2940), toAddr(0x1fff), RefType.DATA,
            SourceType.USER_DEFINED, 0); // Just outside the record.
        long[] targets = {0x2104, 0x2182, 0x21ff};
        for (int i = 0; i < targets.length; i++) {
            references.addMemoryReference(toAddr(0x2950 + i * 0x10), toAddr(targets[i]),
                RefType.READ, SourceType.USER_DEFINED, 0);
        }

        var overlay = memory.createInitializedBlock("references_overlay", toAddr(0x2000),
            16, (byte) 0, monitor, true);
        createData(overlay.getStart(), record);
        createLabel(overlay.getStart(), "references_overlay", true, SourceType.USER_DEFINED);
        references.addMemoryReference(toAddr(0x2980), overlay.getStart(), RefType.DATA,
            SourceType.USER_DEFINED, 0);
        references.addMemoryReference(toAddr(0x2990), overlay.getEnd(), RefType.DATA,
            SourceType.USER_DEFINED, 0);

        // A sparse 256 MiB object exercises destination iteration without allocating its bytes.
        var sparse = memory.createUninitializedBlock("references_sparse", toAddr(0x40000000),
            0x10000000, false);
        createData(sparse.getStart(),
            new ArrayDataType(UnsignedIntegerDataType.dataType, 0x4000000, 4));
        createLabel(sparse.getStart(), "references_sparse", true, SourceType.USER_DEFINED);
        references.addMemoryReference(toAddr(0x29a0), sparse.getEnd(), RefType.DATA,
            SourceType.USER_DEFINED, 0);
    }
}
