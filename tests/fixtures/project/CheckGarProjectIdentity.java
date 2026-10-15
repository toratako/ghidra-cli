import com.google.gson.JsonObject;
import ghidra.app.script.GhidraScript;
import ghidra.util.task.TaskMonitor;
import java.lang.reflect.InvocationTargetException;
import java.nio.file.Files;
import java.nio.file.Path;

public class CheckGarProjectIdentity extends GhidraScript {
  public void run() throws Exception {
    Class<?> caller =
        StackWalker.getInstance(StackWalker.Option.RETAIN_CLASS_REFERENCE)
            .walk(
                frames ->
                    frames
                        .map(StackWalker.StackFrame::getDeclaringClass)
                        .filter(
                            type ->
                                type.getSimpleName().equals("ScriptCommands")
                                    && type.getPackageName().equals("ghidracli.script"))
                        .findFirst()
                        .orElseThrow());
    ClassLoader loader = caller.getClassLoader();
    String prefix =
        caller.getPackageName().substring(0, caller.getPackageName().lastIndexOf('.') + 1);
    var run =
        loader
            .loadClass(prefix + "project.ProjectArchive")
            .getMethod("run", JsonObject.class, TaskMonitor.class);
    var failure =
        loader.loadClass(prefix + "project.ImportSupport").getMethod("failure", Exception.class);
    Path root = Path.of(getScriptArgs()[0]);
    Path parent = root.resolve("literal\\parent");
    for (String operation : new String[] {"archive", "restore"}) {
      Path target = parent.resolve(operation.equals("archive") ? "project" : "restored");
      JsonObject request = new JsonObject();
      request.addProperty("archive_operation", operation);
      request.addProperty("workspace", root.toString());
      request.addProperty("project_path", target.toString());
      request.addProperty(
          "file",
          root.resolve(operation.equals("archive") ? "snapshot.gar" : "input.gar").toString());
      try {
        run.invoke(null, request, monitor);
        throw new AssertionError("Redirected GAR operation succeeded: " + operation);
      } catch (InvocationTargetException error) {
        JsonObject response = (JsonObject) failure.invoke(null, (Exception) error.getCause());
        JsonObject detail = response.getAsJsonObject("detail");
        if (!detail.get("stage").getAsString().equals("project." + operation + "_preflight")
            || !detail.get("cause").getAsString().contains("different project directory")
            || detail.get("published").getAsBoolean()
            || detail.has("remaining_paths")) {
          throw new AssertionError(response.toString());
        }
      }
      for (Path location : new Path[] {parent, root.resolve("literal/parent")}) {
        if (Files.exists(location.resolve(target.getFileName() + ".lock"))) {
          throw new AssertionError("Redirected GAR operation acquired a project lock");
        }
      }
    }
  }
}
