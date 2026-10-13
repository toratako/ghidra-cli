
import ghidra.app.script.GhidraScript;
public class WaitForBridgeCancel extends GhidraScript {
    public void run() throws Exception {
        setEOLComment(toAddr(getScriptArgs()[0]), getScriptArgs()[1]);
        println(getScriptArgs()[1]);
        monitor.setMessage("waiting-for-bridge-cancel");
        long deadline = System.currentTimeMillis() + 30000;
        while (!monitor.isCancelled() && System.currentTimeMillis() < deadline) {
            Thread.sleep(10);
        }
        monitor.checkCancelled();
        throw new IllegalStateException("Cancellation never arrived");
    }
}
