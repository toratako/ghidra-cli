import ghidra.app.script.GhidraScript;

public class CheckBlockSpaces extends GhidraScript {
  public void run() throws Exception {
    var factory = currentProgram.getAddressFactory();
    int overlays = 0;
    for (var space : factory.getAddressSpaces()) {
      if (space.isOverlaySpace()) {
        overlays++;
        if (!space.getName().equals("bank1"))
          throw new IllegalStateException("Unexpected overlay: " + space.getName());
      }
    }
    if (overlays != 1 || factory.getAddressSpace("overflow_bank") != null)
      throw new IllegalStateException("Failed creation leaked an address space");
  }
}
