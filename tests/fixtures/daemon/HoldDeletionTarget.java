import ghidra.app.script.GhidraScript;

public class HoldDeletionTarget extends GhidraScript {
  public void run() {
    currentProgram.addConsumer(currentProgram);
  }
}
