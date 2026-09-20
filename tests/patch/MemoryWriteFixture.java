import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.docking.settings.FormatSettingsDefinition;
import ghidra.framework.model.DomainFile;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.util.DefaultLanguageService;

public class MemoryWriteFixture extends GhidraScript {
    private Program p;
    private Address a(long offset) { return p.getAddressFactory().getDefaultAddressSpace().getAddress(offset); }
    private Data data(long offset) { return p.getListing().getDefinedDataAt(a(offset)); }
    private int width() { return p.getDefaultPointerSize(); }
    private void check(boolean ok, String message) {
        if (!ok) throw new IllegalStateException(message);
    }
    private void pointerBytes(Address address, long value, int length) throws Exception {
        byte[] bytes = new byte[length];
        for (int i = 0; i < length; i++) {
            bytes[p.getMemory().isBigEndian() ? length - i - 1 : i] = (byte)(value >>> (8 * i));
        }
        p.getMemory().setBytes(address, bytes);
    }
    private void pointer(long address, long value, DataType type) throws Exception {
        pointerBytes(a(address), value, type.getLength());
        p.getListing().createData(a(address), type);
    }
    private void create(String name, String languageId) throws Exception {
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(languageId));
        p = new ProgramDB(name, language, language.getDefaultCompilerSpec(), this);
        try {
            int tx = p.startTransaction("memory write fixture");
            try {
                var mem = p.getMemory();
                var listing = p.getListing();
                var dtm = p.getDataTypeManager();
                var refs = p.getReferenceManager();
                mem.createInitializedBlock("sample", a(0x1000), 0x1000, (byte)0, monitor, false).setWrite(false);
                var ptr = new PointerDataType(null, width(), dtm);
                var record = new StructureDataType("Record", 32, dtm);
                record.replaceAtOffset(0, DWordDataType.dataType, 4, "head", "head field");
                record.replaceAtOffset(8, new ArrayDataType(ptr, 2, ptr.getLength()), 2 * width(), "pointers", null);
                record.replaceAtOffset(24, DWordDataType.dataType, 4, "tail", "tail field");
                record.replaceAtOffset(28, StringDataType.dataType, 4, "text", null);
                pointerBytes(a(0x1008), 0x1800, width());
                pointerBytes(a(0x1008 + width()), 0x1808, width());
                mem.setBytes(a(0x101c), new byte[]{'a','b','c',0});
                Data instance = listing.createData(a(0x1000), new TypedefDataType(CategoryPath.ROOT, "RecordAlias", record, dtm));
                var stored = (Structure)instance.getBaseDataType();
                for (int ordinal : new int[]{0, stored.getComponentContaining(24).getOrdinal()}) {
                    var field = stored.getComponent(ordinal);
                    FormatSettingsDefinition.DEF.setChoice(field.getDefaultSettings(), FormatSettingsDefinition.DECIMAL);
                    EndianSettingsDefinition.DEF.setChoice(field.getDefaultSettings(), EndianSettingsDefinition.BIG);
                }
                FormatSettingsDefinition.DEF.setChoice(instance.getComponent(0), FormatSettingsDefinition.BINARY);
                listing.setComment(a(0x1000), CodeUnit.EOL_COMMENT, "keep record comment");
                p.getSymbolTable().createLabel(a(0x1000), "kept_record", SourceType.USER_DEFINED);
                refs.addMemoryReference(a(0x1000), a(0x1800), RefType.DATA, SourceType.USER_DEFINED, 0);
                refs.addMemoryReference(a(0x1900), a(0x1000), RefType.DATA, SourceType.USER_DEFINED, 0);
                p.getEquateTable().createEquate("record_equate", 0).addReference(a(0x1000), 0);

                if (languageId.startsWith("x86")) {
                    mem.setBytes(a(0x1100), new byte[]{0x66,(byte)0x90});
                    check(new DisassembleCommand(a(0x1100), new AddressSet(a(0x1100), a(0x1101)), false)
                        .applyTo(p, monitor), "define instruction");
                    listing.createData(a(0x1102), DWordDataType.dataType);
                    refs.addMemoryReference(a(0x1100), a(0x1800), RefType.DATA, SourceType.USER_DEFINED, 0);
                    p.getEquateTable().createEquate("instruction_equate", 1).addReference(a(0x1100), 0);
                } else if (languageId.startsWith("MIPS")) {
                    mem.setBytes(a(0x1100), new byte[]{0x10,0,0,1,0x24,2,0,1});
                    check(new DisassembleCommand(a(0x1100), new AddressSet(a(0x1100), a(0x1107)), false)
                        .applyTo(p, monitor), "define branch and delay slot");
                    check(listing.getInstructionAt(a(0x1104)).isInDelaySlot(), "fixture delay slot");
                }

                for (int i = 0; i <= 5; i++) pointer(0x1200 + 8 * i, 0x1800, ptr);
                SourceType[] sources = {SourceType.USER_DEFINED, SourceType.IMPORTED, SourceType.ANALYSIS, SourceType.DEFAULT};
                for (int i = 0; i < sources.length; i++) {
                    Reference ref = refs.addMemoryReference(a(0x1208 + 8 * i), a(0x1820), RefType.DATA, sources[i], 0);
                    refs.setPrimary(ref, true);
                }
                refs.addShiftedMemReference(a(0x1228), a(0x1800), 2, RefType.DATA, SourceType.DEFAULT, 0);
                var offsetPtr = new PointerTypedef("ComponentPointer", null, width(), dtm);
                ComponentOffsetSettingsDefinition.DEF.setValue(offsetPtr.getDefaultSettings(), 4);
                pointer(0x1230, 0x1804, offsetPtr);
                pointer(0x1238, 0x100, new PointerTypedef("RelativePointer", null, width(), dtm, PointerType.RELATIVE));
                pointer(0x1240, 0x1800, new PointerTypedef("ImagePointer", null, width(), dtm, PointerType.IMAGE_BASE_RELATIVE));
                var union = new UnionDataType(CategoryPath.ROOT, "PointerUnion", dtm);
                union.add(ptr, "pointer", null);
                union.add(new ArrayDataType(ByteDataType.dataType, width(), 1), "bytes", null);
                pointer(0x1248, 0x1800, union);
                refs.addMemoryReference(a(0x1248), a(0x1800), RefType.DATA, SourceType.DEFAULT, 0);
                pointer(0x1250, 0x1800, ptr);
                refs.addExternalReference(a(0x1250), "library", "external_target", null, SourceType.IMPORTED, 0, RefType.DATA);
                var masked = new PointerTypedef("MaskedPointer", null, width(), dtm);
                OffsetMaskSettingsDefinition.DEF.setValue(masked.getDefaultSettings(), 0xffff);
                pointer(0x1258, 0x1800, masked);
                pointer(0x1260, 0, ptr);
                pointer(0x1268, 0x1800, new PointerDataType(null, 2, dtm));
                pointer(0x1270, 0x1800, new ShiftedAddressDataType(dtm));

                mem.setBytes(a(0x1300), new byte[]{'a','b','c',0});
                listing.createData(a(0x1300), StringDataType.dataType, 4);
                mem.setBytes(a(0x1310), new byte[]{'a','b','c',0});
                listing.createData(a(0x1310), new ArrayDataType(CharDataType.dataType, 4, 1));
                mem.setBytes(a(0x1320), new byte[]{'a','b','c',0});
                listing.createData(a(0x1320), TerminatedStringDataType.dataType);
                mem.setBytes(a(0x1330), new byte[]{3,'a','b','c'});
                listing.createData(a(0x1330), PascalString255DataType.dataType);
                mem.setShort(a(0x1340), (short)'a');
                mem.setShort(a(0x1342), (short)'b');
                listing.createData(a(0x1340), TerminatedUnicodeDataType.dataType);
                var text = new StructureDataType("NestedString", 8, dtm);
                text.replaceAtOffset(0, TerminatedStringDataType.dataType, 4, "text", null);
                text.replaceAtOffset(4, DWordDataType.dataType, 4, "number", null);
                mem.setBytes(a(0x1350), new byte[]{'a','b','c',0});
                listing.createData(a(0x1350), text);
                mem.setBytes(a(0x1360), new byte[]{(byte)0x81,1});
                listing.createData(a(0x1360), UnsignedLeb128DataType.dataType);
                mem.setShort(a(0x1370), (short)3);
                mem.setBytes(a(0x1372), new byte[]{'a','b','c'});
                listing.createData(a(0x1370), PascalStringDataType.dataType);
                listing.createData(a(0x1380), new ArrayDataType(ByteDataType.dataType, 0, 1));

                pointerBytes(a(0x1700), 0x1800, width());
                mem.createByteMappedBlock("byte_alias", a(0x3000), a(0x1700), 8, false);
                mem.createBitMappedBlock("bit_alias", a(0x4000), a(0x1700), 8, false);
                listing.createData(a(0x3000), ptr);
                var overlay = mem.createInitializedBlock("overlay", a(0x1000), 0x1000, (byte)0, monitor, true);
                for (int i = 0; i < 2; i++) {
                    Address slot = overlay.getStart().add(i == 0 ? 0x200 : 0xff8);
                    pointerBytes(slot, i == 0 ? 0x1800 : 0x2800, width());
                    listing.createData(slot, ptr);
                }
            } finally { p.endTransaction(tx, true); }
            state.getProject().getProjectData().getRootFolder().createFile(name, p, monitor);
        } finally { p.release(this); }
    }

    private void ref(long from, long to, SourceType source, boolean primary) {
        Reference ref = p.getReferenceManager().getReference(a(from), a(to), 0);
        check(ref != null && ref.getSource() == source && ref.isPrimary() == primary,
            "reference " + Long.toHexString(from) + " -> " + Long.toHexString(to));
    }

    private void verify(String mode) throws Exception {
        var listing = p.getListing();
        var refs = p.getReferenceManager();
        if (mode.equals("data")) {
            Data record = data(0x1000);
            check(record != null && record.getDataType().getName().equals("RecordAlias") && record.getLength() == 32, "record definition");
            check(p.getMemory().getByte(a(0x1001)) == (byte)0xaa, "changed scalar byte");
            check(FormatSettingsDefinition.DEF.getChoice(record.getComponent(0)) == FormatSettingsDefinition.BINARY, "instance format");
            var structure = (Structure)record.getBaseDataType();
            for (int offset : new int[]{0, 24}) {
                var field = structure.getComponentContaining(offset);
                check(FormatSettingsDefinition.DEF.getChoice(field.getDefaultSettings()) == FormatSettingsDefinition.DECIMAL, "field format");
                check(EndianSettingsDefinition.DEF.getChoice(field.getDefaultSettings()) == EndianSettingsDefinition.BIG, "field endian");
            }
            check("keep record comment".equals(listing.getComment(CodeUnit.EOL_COMMENT, a(0x1000))), "comment");
            check(p.getSymbolTable().getPrimarySymbol(a(0x1000)).getName().equals("kept_record"), "label");
            check(p.getEquateTable().getEquates(a(0x1000), 0).size() == 1, "data equate");
            ref(0x1000, 0x1800, SourceType.USER_DEFINED, true);
            ref(0x1900, 0x1000, SourceType.USER_DEFINED, true);
            ref(0x1008, 0x1900, SourceType.DEFAULT, true);
            ref(0x1008 + width(), 0x1808, SourceType.DEFAULT, true);
            check(refs.getReference(a(0x1008), a(0x1800), 0) == null, "old nested pointer reference");
            check(listing.getInstructionAt(a(0x1100)) != null && data(0x1102) != null, "mixed write definitions");
            ref(0x1100, 0x1800, SourceType.USER_DEFINED, true);
            check(p.getEquateTable().getEquates(a(0x1100), 0).size() == 1, "unchanged instruction equate");
            check(!p.getMemory().getBlock(a(0x1000)).isWrite(), "memory permissions");
            check(data(0x1380) != null && data(0x1380).getNumComponents() == 0, "empty array definition");
        } else if (mode.equals("cleared")) {
            check(listing.getInstructionAt(a(0x1100)) == null, "changed instruction still defined");
            check(data(0x1102) != null, "neighbor data lost");
            check(refs.getReferencesFrom(a(0x1100)).length == 0, "cleared instruction refs");
            check(p.getEquateTable().getEquates(a(0x1100), 0).isEmpty(), "cleared instruction equate");
        } else if (mode.equals("delay")) {
            check(listing.getInstructionAt(a(0x1100)) == null && listing.getInstructionAt(a(0x1104)) == null, "delay slot clearing unit");
        } else if (mode.equals("pointers")) {
            ref(0x1200, 0x1900, SourceType.DEFAULT, true);
            SourceType[] sources = {SourceType.USER_DEFINED, SourceType.IMPORTED, SourceType.ANALYSIS, SourceType.DEFAULT};
            for (int i = 0; i < sources.length; i++) {
                long address = 0x1208 + 8 * i;
                ref(address, 0x1820, sources[i], true);
                check(refs.getReferencesFrom(a(address)).length == 1, "protected operand gained a reference");
            }
            var shifted = refs.getReference(a(0x1228), a(0x1800), 0);
            check(shifted != null && shifted.isShiftedReference() && refs.getReferencesFrom(a(0x1228)).length == 1, "shifted reference overwritten");
            var offset = refs.getReference(a(0x1230), a(0x1904), 0);
            check(offset instanceof OffsetReference && ((OffsetReference)offset).getOffset() == 4
                && ((OffsetReference)offset).getBaseAddress().equals(a(0x1900)), "component offset reference");
            ref(0x1238, 0x12b8, SourceType.DEFAULT, true);
            ref(0x1240, p.getImageBase().getOffset() + 0x1900, SourceType.DEFAULT, true);
            ref(0x1248, 0x1800, SourceType.DEFAULT, true);
            var external = refs.getReferencesFrom(a(0x1250));
            check(external.length == 1 && external[0].isExternalReference() && external[0].getSource() == SourceType.IMPORTED && external[0].isPrimary(), "external reference lost");
            ref(0x1258, 0x1800, SourceType.DEFAULT, true);
            ref(0x1260, 0x1900, SourceType.DEFAULT, true);
            ref(0x1268, 0x1900, SourceType.DEFAULT, true);
            ref(0x1270, 0x1900L << p.getDataTypeManager().getDataOrganization().getPointerShift(), SourceType.DEFAULT, true);
            for (int i : new int[]{0, 6, 7, 8, 12, 13, 14}) {
                var all = refs.getReferencesFrom(a(0x1200 + 8 * i));
                check(all.length == 1, "old automatic reference retained at slot " + i);
            }
        } else if (mode.equals("null")) {
            check(data(0x1200) != null && refs.getReferencesFrom(a(0x1200)).length == 0, "null pointer reference");
        } else if (mode.equals("strings")) {
            for (long address : new long[]{0x1300,0x1310,0x1320,0x1330,0x1350,0x1360,0x1370}) {
                check(data(address) != null, "string/data definition " + Long.toHexString(address));
            }
            check(data(0x1300).getLength() == 4 && data(0x1310).getLength() == 4, "fixed strings shrank");
            check(data(0x1320).getValue().equals("xyz") && data(0x1320).getLength() == 4, "terminated string");
            check(data(0x1330).getValue().equals("xyz") && data(0x1330).getLength() == 4, "pascal string");
            check(data(0x1340).getValue().equals("xy") && data(0x1340).getLength() == 6, "unicode string");
            check(data(0x1350).getComponent(0).getValue().equals("xyz") && data(0x1350).getLength() == 8, "nested string");
        } else if (mode.equals("overlay")) {
            var space = p.getAddressFactory().getAddressSpace("overlay");
            Reference inside = refs.getReference(space.getAddress(0x1200), space.getAddress(0x1900), 0);
            Reference outside = refs.getReference(space.getAddress(0x1ff8), a(0x2900), 0);
            check(inside != null && outside != null, "overlay pointer targets");
            check(refs.getReferencesFrom(space.getAddress(0x1200)).length == 1 && refs.getReferencesFrom(space.getAddress(0x1ff8)).length == 1, "stale overlay references");
        } else throw new IllegalArgumentException(mode);
    }

    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args[0].equals("create")) { create(args[1], args[2]); return; }
        p = currentProgram;
        verify(args[0]);
        Object reader = new Object();
        p = (Program)currentProgram.getDomainFile().getReadOnlyDomainObject(reader, DomainFile.DEFAULT_VERSION, monitor);
        try { verify(args[0]); } finally { p.release(reader); }
        println("verified:" + args[0]);
    }
}
