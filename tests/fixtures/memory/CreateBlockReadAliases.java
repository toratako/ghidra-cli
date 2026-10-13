import ghidra.app.script.GhidraScript;

public class CreateBlockReadAliases extends GhidraScript {
  public void run() throws Exception {
    var space = currentProgram.getAddressFactory().getDefaultAddressSpace();
    var memory = currentProgram.getMemory();
    memory.createByteMappedBlock(
        "byte_alias", space.getAddress(0x6000), space.getAddress(0x5000), 16, false);
    memory.createBitMappedBlock(
        "bit_alias", space.getAddress(0x7000), space.getAddress(0x5000), 8, false);
  }
}
