import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.CodeUnit;

public class CheckMovedOverlay extends GhidraScript {
  public void run() throws Exception {
    var space = currentProgram.getAddressFactory().getAddressSpace("bank");
    var address = space.getAddressInThisSpaceOnly(0x6000);
    if (currentProgram.getMemory().getByte(address) != (byte) 0xab) {
      throw new IllegalStateException("Overlay bytes did not move");
    }
    if (!"overlay comment"
        .equals(currentProgram.getListing().getComment(CodeUnit.EOL_COMMENT, address))) {
      throw new IllegalStateException("Overlay comment did not move");
    }
    // OverlayAddressSpace.getAddress falls back to the physical space at
    // unbacked offsets; inspect the overlay's former address explicitly.
    if (currentProgram.getMemory().getBlock(space.getAddressInThisSpaceOnly(0x2000)) != null) {
      throw new IllegalStateException("Overlay's previous block remains");
    }
  }
}
