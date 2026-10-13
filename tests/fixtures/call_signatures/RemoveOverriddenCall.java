import ghidra.app.script.GhidraScript;

public class RemoveOverriddenCall extends GhidraScript {
  public void run() throws Exception {
    currentProgram.getListing().clearCodeUnits(toAddr(0x1005), toAddr(0x1009), false);
  }
}
