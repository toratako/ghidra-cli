import ghidra.app.script.GhidraScript;

public class RebaseMappedSources extends GhidraScript {
  public void run() throws Exception {
    var memory = currentProgram.getMemory();
    var space = currentProgram.getAddressFactory().getDefaultAddressSpace();
    var overlay = memory.getBlock("rebase_overlay").getStart().getAddressSpace();
    if (getScriptArgs()[0].equals("create")) {
      var source = space.getAddress(0x3040);
      memory.createByteMappedBlock("mapped_bytes", space.getAddress(0x8000), source, 0x10, false);
      memory.createBitMappedBlock("mapped_bits", space.getAddress(0x8100), source, 0x10, false);
      memory.createByteMappedBlock("mapped_overlay", space.getAddress(0x8200), source, 0x10, true);
      memory.createByteMappedBlock(
          "mapped_overlay_source",
          space.getAddress(0x8300),
          overlay.getAddressInThisSpaceOnly(0xfffffffffffff000L),
          0x10,
          false);
      return;
    }

    long delta = currentProgram.getImageBase().getOffset() - 0x1000;
    for (String name : new String[] {"mapped_bytes", "mapped_bits", "mapped_overlay"}) {
      var block = memory.getBlock(name);
      var range = block.getSourceInfos().get(0).getMappedRange().orElseThrow();
      int sourceLength = name.equals("mapped_bits") ? 2 : 0x10;
      if (!range.getMinAddress().equals(space.getAddress(0x3040 + delta))
          || !range.getMaxAddress().equals(space.getAddress(0x3040 + delta + sourceLength - 1))) {
        throw new IllegalStateException("Mapped source did not move: " + name + " " + range);
      }
      int expectedByte = name.equals("mapped_bits") ? 1 : 0x55;
      if (memory.getByte(block.getStart()) != expectedByte) {
        throw new IllegalStateException("Mapped bytes changed: " + name);
      }
    }
    var stationary =
        memory
            .getBlock("mapped_overlay_source")
            .getSourceInfos()
            .get(0)
            .getMappedRange()
            .orElseThrow();
    if (!stationary.getMinAddress().equals(overlay.getAddressInThisSpaceOnly(0xfffffffffffff000L))
        || !stationary
            .getMaxAddress()
            .equals(overlay.getAddressInThisSpaceOnly(0xfffffffffffff00fL))) {
      throw new IllegalStateException("Overlay mapped source moved: " + stationary);
    }
  }
}
