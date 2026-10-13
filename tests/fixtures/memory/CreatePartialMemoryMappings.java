import ghidra.app.script.GhidraScript;

public class CreatePartialMemoryMappings extends GhidraScript {
  public void run() throws Exception {
    var memory = currentProgram.getMemory();
    var space = currentProgram.getAddressFactory().getDefaultAddressSpace();
    var source = space.getAddress(0x1000);
    memory.createByteMappedBlock("partial_bytes", space.getAddress(0x2000), source, 32, false);
    memory.createBitMappedBlock("partial_bits", space.getAddress(0x3000), source, 256, false);
    memory.createByteMappedBlock(
        "nested_bytes", space.getAddress(0x1800), space.getAddress(0x2000), 32, false);
    memory.createUninitializedBlock("unknown_source", source.add(16), 16, false);
    memory.createInitializedBlock(
        "chunk_source", space.getAddress(0x10000), 0xc000, (byte) 0xee, monitor, false);
    memory.setBytes(space.getAddress(0x13ffe), new byte[] {0x12, 0x34, 0x56, 0x78});
    memory.createByteMappedBlock(
        "chunk_alias", space.getAddress(0x30000), space.getAddress(0x10000), 0xc000, false);
    memory.createByteMappedBlock(
        "chunk_nested", space.getAddress(0x20000), space.getAddress(0x30000), 0xc000, false);
    var header =
        memory
            .createInitializedBlock(
                "headers",
                ghidra.program.model.address.AddressSpace.OTHER_SPACE.getAddress(0),
                new java.io.ByteArrayInputStream(new byte[] {(byte) 0xca, (byte) 0xfe}),
                2,
                monitor,
                true)
            .getStart();
    memory.createByteMappedBlock("loaded_header_view", space.getAddress(0x40000), header, 2, false);
    createData(
        space.getAddress(0x1800),
        new ghidra.program.model.data.ArrayDataType(
            ghidra.program.model.data.CharDataType.dataType, 16, 1));
  }
}
