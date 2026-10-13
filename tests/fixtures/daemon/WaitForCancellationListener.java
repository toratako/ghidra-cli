
import ghidra.app.script.GhidraScript;
import ghidra.util.task.CancelledListener;
import java.nio.file.Files;
import java.nio.file.Path;
public class WaitForCancellationListener extends GhidraScript {
    private CancelledListener listener;
    public void run() throws Exception {
        Path entered = Path.of(getScriptArgs()[0]);
        Path release = Path.of(getScriptArgs()[1]);
        listener = () -> {
            try {
                Files.writeString(entered, "entered");
                long deadline = System.currentTimeMillis() + 15000;
                while (!Files.exists(release)) {
                    if (System.currentTimeMillis() >= deadline) {
                        throw new IllegalStateException("Cancellation listener was not released");
                    }
                    Thread.sleep(10);
                }
            } catch (Exception error) { throw new IllegalStateException(error); }
            throw new AssertionError("Cancellation listener assertion");
        };
        monitor.addCancelledListener(listener);
        monitor.setMessage("waiting-for-listener-cancel");
        long deadline = System.currentTimeMillis() + 30000;
        while (!monitor.isCancelled() && System.currentTimeMillis() < deadline) Thread.sleep(10);
        monitor.checkCancelled();
        throw new IllegalStateException("Cancellation never arrived");
    }
}
