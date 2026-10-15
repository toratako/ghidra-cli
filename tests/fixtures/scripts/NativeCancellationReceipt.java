import ghidra.app.script.GhidraScript;
import ghidra.util.exception.CancelledException;

public class NativeCancellationReceipt extends GhidraScript {
  public void run() throws Exception {
    if (monitor.isCancelled()) throw new AssertionError("Unexpected pre-cancelled request");
    println("before native cancellation");
    throw new CancelledException();
  }
}
