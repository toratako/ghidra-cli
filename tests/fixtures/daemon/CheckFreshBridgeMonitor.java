import ghidra.app.script.GhidraScript;

public class CheckFreshBridgeMonitor extends GhidraScript {
  public void run() throws Exception {
    monitor.checkCancelled();
    println("fresh-monitor:" + currentProgram.getName());
  }
}
