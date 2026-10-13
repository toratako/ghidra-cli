import com.google.gson.JsonObject;
import ghidra.app.script.GhidraScript;
import ghidra.framework.model.ProjectLocator;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import java.lang.reflect.InvocationTargetException;
import java.nio.file.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.zip.ZipFile;

/** Keep a cleanup scratch file alive throughout traversal, without timing sleeps. */
public class CheckGarSnapshot extends GhidraScript {
    public void run() throws Exception {
        Class<?> caller = StackWalker.getInstance(StackWalker.Option.RETAIN_CLASS_REFERENCE)
            .walk(frames -> frames.map(StackWalker.StackFrame::getDeclaringClass)
                .filter(type -> type.getSimpleName().equals("ScriptCommands")
                    && type.getPackageName().equals("ghidracli.script")).findFirst().orElseThrow());
        ClassLoader loader = caller.getClassLoader();
        var run = loader.loadClass("ghidracli.project.ProjectArchive")
            .getMethod("run", JsonObject.class, TaskMonitor.class);
        Path root = Files.createDirectory(Path.of(getScriptArgs()[0]).resolve("snapshot-probe"));
        Path source = Path.of(getScriptArgs()[1]);
        Path gar = root.resolve("snapshot.gar");
        for (String operation : new String[] {"archive", "restore"}) {
            Path target = root.resolve("restored");
            JsonObject request = new JsonObject();
            request.addProperty("archive_operation", operation);
            request.addProperty("workspace", root.toString());
            request.addProperty("project_path", (operation.equals("archive") ? source : target).toString());
            request.addProperty("file", gar.toString());
            CountDownLatch release = new CountDownLatch(1);
            CompletableFuture<Void> created = new CompletableFuture<>();
            CompletableFuture<Void> cleaned = new CompletableFuture<>();
            boolean[] inspected = {false};
            boolean[] writable = {false};
            TaskMonitorAdapter probe = new TaskMonitorAdapter(true) {
                @Override public void checkCancelled() throws CancelledException {
                    super.checkCancelled();
                    if (inspected[0] || !StackWalker.getInstance().walk(frames -> frames.anyMatch(
                            frame -> frame.getClassName().endsWith(".ProjectArchive")
                                && frame.getMethodName().equals("inspectFolder")))) return;
                    inspected[0] = true;
                    try (var children = Files.list(root)) {
                        Path snapshot = children.filter(path -> path.getFileName().toString().startsWith("ghidra-cli-"))
                            .findFirst().orElseThrow().resolve("snapshot");
                        ProjectLocator locator = new ProjectLocator(snapshot.getParent().toString(), "snapshot");
                        // This is a fresh private copy with no inherited lock
                        // artifacts. Its lock can only belong to the inspector.
                        writable[0] = Files.exists(locator.getProjectLockFile().toPath());
                        if (!writable[0]) return;
                        // Native LocalFileSystem starts Database-Item-Cleanup only
                        // for a writable open. Model its create/delete window at
                        // that observable boundary and hold it through packing or
                        // moving the snapshot. This also catches transient files
                        // being silently archived instead of merely disappearing.
                        Thread cleanup = new Thread(() -> {
                            try {
                                Path scratch = Files.createTempFile(Path.of(snapshot + ".rep").resolve("idata"), "tmp", ".tmp");
                                created.complete(null);
                                if (!release.await(30, TimeUnit.SECONDS)) throw new AssertionError("Traversal did not finish");
                                Files.deleteIfExists(scratch);
                                cleaned.complete(null);
                            } catch (Throwable error) {
                                created.completeExceptionally(error);
                                cleaned.completeExceptionally(error);
                            }
                        }, "controlled-database-cleanup");
                        cleanup.setDaemon(true);
                        cleanup.start();
                        created.get(30, TimeUnit.SECONDS);
                    } catch (Exception error) { throw new IllegalStateException(error); }
                }
            };
            try {
                JsonObject result = (JsonObject) run.invoke(null, request, probe);
                if (result.get("files").getAsInt() != 3 || result.get("folders").getAsInt() != 3) {
                    throw new AssertionError(result.toString());
                }
                if (!inspected[0]) throw new AssertionError("Snapshot inspection was not exercised");
                if (operation.equals("archive")) {
                    try (ZipFile zip = new ZipFile(gar.toFile())) {
                        if (zip.stream().anyMatch(entry -> entry.getName().matches(".*/tmp[^/]*\\.tmp"))) {
                            throw new AssertionError("Cleanup scratch file was archived");
                        }
                    }
                } else {
                    try (var paths = Files.walk(Path.of(target + ".rep"))) {
                        if (paths.anyMatch(path -> path.getFileName().toString().matches("tmp.*\\.tmp"))) {
                            throw new AssertionError("Cleanup scratch file was restored");
                        }
                    }
                }
                if (writable[0]) throw new AssertionError("Snapshot inspection opened a writable project");
            } finally {
                release.countDown();
                if (writable[0]) cleaned.get(30, TimeUnit.SECONDS);
            }
        }
        checkMissingData(loader, root);
        println("snapshot inspection verified");
    }

    private void checkMissingData(ClassLoader loader, Path root) throws Exception {
        var write = loader.loadClass("ghidracli.project.GarFile")
            .getDeclaredMethod("write", Path.class, String.class, Path.class, TaskMonitor.class);
        write.setAccessible(true);
        Path project = root.resolve("missing");
        Path data = Files.createDirectories(Path.of(project + ".rep").resolve("idata"));
        Path file = Files.writeString(data.resolve("database"), "saved project data");
        TaskMonitorAdapter probe = new TaskMonitorAdapter(true) {
            int visits;
            @Override public void checkCancelled() throws CancelledException {
                super.checkCancelled();
                // Files.walk has yielded the sole file, but the visitor has not
                // read its attributes or opened it. Do not hide real data loss.
                if (++visits == 2) {
                    try { Files.delete(file); }
                    catch (Exception error) { throw new IllegalStateException(error); }
                }
            }
        };
        try {
            write.invoke(null, project, "missing", root.resolve("missing.gar"), probe);
            throw new AssertionError("Missing project data was ignored");
        } catch (InvocationTargetException error) {
            if (!(error.getCause() instanceof NoSuchFileException)) throw error;
        }
    }
}
