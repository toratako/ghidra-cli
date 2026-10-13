import ghidra.app.script.GhidraScript;

public class CheckRemovedOverlay extends GhidraScript {
  public void run() throws Exception {
    if (currentProgram.getAddressFactory().getAddressSpace("bank") != null) {
      throw new IllegalStateException("Last block deletion retained overlay space");
    }
  }
}
