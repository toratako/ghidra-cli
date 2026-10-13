import ghidra.app.script.GhidraScript;

public class HoldJobResults extends GhidraScript {
  public void run() throws Exception {
    monitor.setMessage("holding-for-result-recovery");
    long deadline = System.currentTimeMillis() + 30000;
    while (System.currentTimeMillis() < deadline) {
      monitor.checkCancelled();
      Thread.sleep(10);
    }
    throw new IllegalStateException("Test did not cancel the script");
  }
}
