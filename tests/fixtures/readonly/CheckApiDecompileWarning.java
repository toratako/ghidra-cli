import com.google.gson.JsonArray;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import java.lang.reflect.InvocationTargetException;

public class CheckApiDecompileWarning extends GhidraScript {
  public void run() throws Exception {
    Class<?> caller =
        StackWalker.getInstance(StackWalker.Option.RETAIN_CLASS_REFERENCE)
            .walk(
                frames ->
                    frames
                        .map(StackWalker.StackFrame::getDeclaringClass)
                        .filter(type -> type.getName().equals("ghidracli.script.ScriptCommands"))
                        .findFirst()
                        .orElseThrow());
    var collect =
        caller
            .getClassLoader()
            .loadClass("ghidracli.analysis.DecompileWarnings")
            .getDeclaredMethod("collect", DecompileResults.class, TaskMonitor.class);
    collect.setAccessible(true);
    var engine = new DecompInterface();
    try {
      if (!engine.openProgram(currentProgram))
        throw new IllegalStateException(engine.getLastMessage());
      var result = engine.decompileFunction(getFunctionAt(toAddr(0x1040)), 30, monitor);
      if (!result.decompileCompleted()) throw new IllegalStateException(result.getErrorMessage());
      var message = DecompileResults.class.getDeclaredField("errMsg");
      message.setAccessible(true);
      message.set(result, "  API-only diagnostic\nsecond line  ");
      var warnings = (JsonArray) collect.invoke(null, result, monitor);
      if (warnings.size() != 3) throw new IllegalStateException(warnings.toString());
      var diagnostic = warnings.get(0).getAsJsonObject();
      if (!"decompiler".equals(diagnostic.get("source").getAsString())
          || !"API-only diagnostic\nsecond line".equals(diagnostic.get("message").getAsString())
          || !diagnostic.get("address").isJsonNull())
        throw new IllegalStateException(diagnostic.toString());
      // Cancel after collection has entered the native markup tree. No
      // warning subset may escape as a completed read, and a later scan
      // must still return both comment diagnostics and the API message.
      var cancelled =
          new TaskMonitorAdapter(true) {
            private int checks;

            @Override
            public void checkCancelled() throws CancelledException {
              if (++checks == 6) cancel();
              super.checkCancelled();
            }
          };
      try {
        collect.invoke(null, result, cancelled);
        throw new IllegalStateException(
            "Warning scan ignored cancellation during markup traversal");
      } catch (InvocationTargetException failure) {
        if (!(failure.getCause() instanceof CancelledException)) throw failure;
      }
      if (!warnings.equals(collect.invoke(null, result, monitor)))
        throw new IllegalStateException("Warning scan did not recover after cancellation");
    } finally {
      engine.closeProgram();
      engine.dispose();
    }
  }
}
