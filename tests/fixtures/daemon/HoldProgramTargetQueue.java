import ghidra.app.script.GhidraScript;

public class HoldProgramTargetQueue extends GhidraScript {
  public void run() throws Exception {
    var release = new java.io.File(getScriptArgs()[0]);
    monitor.setMessage("holding-program-target-queue");
    long deadline = System.currentTimeMillis() + 30000;
    while (!release.exists()) {
      monitor.checkCancelled();
      if (System.currentTimeMillis() > deadline) {
        throw new IllegalStateException("Program target queue was not released");
      }
      Thread.sleep(10);
    }
  }
}
