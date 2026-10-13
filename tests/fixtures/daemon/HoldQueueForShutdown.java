
import ghidra.app.script.GhidraScript;
public class HoldQueueForShutdown extends GhidraScript {
    public void run() throws Exception {
        java.io.File release = new java.io.File(getScriptArgs()[0]);
        monitor.setMessage("holding-queue-for-shutdown");
        long deadline = System.currentTimeMillis() + 60000;
        while (!release.exists()) {
            if (System.currentTimeMillis() > deadline) {
                throw new IllegalStateException("Queue was not released");
            }
            Thread.sleep(10);
        }
    }
}
