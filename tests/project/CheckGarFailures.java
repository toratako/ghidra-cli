import com.google.gson.JsonObject;
import ghidra.app.script.GhidraScript;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import java.lang.reflect.InvocationTargetException;
import java.nio.file.*;

/** Exercise cancellation after staging starts and collisions during publication. */
public class CheckGarFailures extends GhidraScript {
    public void run() throws Exception {
        Class<?> caller = StackWalker.getInstance(StackWalker.Option.RETAIN_CLASS_REFERENCE)
            .walk(frames -> frames.map(StackWalker.StackFrame::getDeclaringClass)
                .filter(type -> type.getSimpleName().equals("ScriptCommands")
                    && type.getPackageName().equals("ghidracli")).findFirst().orElseThrow());
        ClassLoader loader = caller.getClassLoader();
        var run = loader.loadClass("ghidracli.ProjectArchive").getMethod("run", JsonObject.class, TaskMonitor.class);
        var failure = loader.loadClass("ghidracli.ImportSupport").getMethod("failure", Exception.class);
        Path root = Path.of(getScriptArgs()[0]);
        Path source = Path.of(getScriptArgs()[1]);
        Path gar = Path.of(getScriptArgs()[2]);
        for (String operation : new String[] {"archive", "restore"}) {
            for (boolean cancel : new boolean[] {true, false}) {
                Path target = root.resolve("failure-target");
                Path output = root.resolve("failure-output.gar");
                JsonObject request = new JsonObject();
                request.addProperty("archive_operation", operation);
                request.addProperty("workspace", root.toString());
                request.addProperty("project_path", (operation.equals("archive") ? source : target).toString());
                request.addProperty("file", (operation.equals("archive") ? output : gar).toString());
                boolean[] injected = {false};
                TaskMonitorAdapter probe = new TaskMonitorAdapter(true) {
                    @Override public void checkCancelled() throws CancelledException {
                        if (!injected[0]) {
                            try (var children = Files.list(root)) {
                                for (Path path : (Iterable<Path>) children::iterator) {
                                    String name = path.getFileName().toString();
                                    if (!name.startsWith("ghidra-cli-gar-") && !name.startsWith("ghidra-cli-restore-")) continue;
                                    if (cancel && Files.isDirectory(path.resolve("snapshot.rep/idata"))) {
                                        injected[0] = true;
                                        cancel();
                                    } else if (!cancel && operation.equals("archive") && Files.exists(path.resolve("archive.gar"))) {
                                        Files.writeString(output, "competing output", StandardOpenOption.CREATE_NEW);
                                        injected[0] = true;
                                    } else if (!cancel && operation.equals("restore") && Files.isDirectory(Path.of(target + ".rep"))) {
                                        Files.writeString(Path.of(target + ".gpr"), "competing marker", StandardOpenOption.CREATE_NEW);
                                        injected[0] = true;
                                    }
                                }
                            } catch (Exception error) { throw new IllegalStateException(error); }
                        }
                        super.checkCancelled();
                    }
                };
                try {
                    run.invoke(null, request, probe);
                    throw new AssertionError("Faulted operation succeeded: " + operation);
                } catch (InvocationTargetException error) {
                    JsonObject response = (JsonObject) failure.invoke(null, (Exception) error.getCause());
                    JsonObject detail = response.getAsJsonObject("detail");
                    if (!injected[0] || detail.get("published").getAsBoolean() || detail.has("remaining_paths")) {
                        throw new AssertionError(response.toString());
                    }
                    if (detail.get("cancelled").getAsBoolean() != cancel) throw new AssertionError(response.toString());
                    if (!cancel && !detail.get("stage").getAsString().endsWith("_publish")) throw new AssertionError(response.toString());
                }
                if (Files.exists(Path.of(target + ".rep"))) throw new AssertionError("Incomplete .rep retained");
                if (!cancel) {
                    Path competitor = operation.equals("archive") ? output : Path.of(target + ".gpr");
                    if (!Files.readString(competitor).startsWith("competing ")) throw new AssertionError("Competitor overwritten");
                    Files.delete(competitor);
                } else if (Files.exists(output) || Files.exists(Path.of(target + ".gpr"))) {
                    throw new AssertionError("Cancelled operation published output");
                }
                try (var paths = Files.list(root)) {
                    if (paths.anyMatch(path -> path.getFileName().toString().startsWith("ghidra-cli-"))) {
                        throw new AssertionError("Staging not cleaned");
                    }
                }
            }
        }
    }
}
