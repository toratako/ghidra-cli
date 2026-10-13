import ghidra.app.script.GhidraScript;
import generic.util.LockFactory;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectLocator;
import ghidra.formats.gfilesystem.*;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;
import java.io.File;
import java.lang.reflect.*;
import java.nio.file.*;

/** Exercise upstream GAR code independently of ghidracli's implementation. */
public class NativeGar extends GhidraScript {
    public void run() throws Exception {
        String[] args = getScriptArgs();
        Path path = Path.of(args[1]);
        File archive = new File(args[2]);
        ClassLoader loader = GhidraScript.class.getClassLoader();
        if (args[0].equals("archive")) {
            // ArchiveTask only needs project identity before doing real disk
            // I/O. Keep Ghidra's source lock without opening writable databases,
            // which would launch cleanup racing the native writer itself.
            var locator = new ProjectLocator(path.getParent().toString(), path.getFileName().toString());
            var lock = LockFactory.createFileLocker(locator.getProjectLockFile());
            if (!lock.lock()) throw new AssertionError("Native archive source is locked");
            try {
                Project project = (Project) Proxy.newProxyInstance(Project.class.getClassLoader(),
                    new Class<?>[] {Project.class}, (proxy, method, values) -> {
                        switch (method.getName()) {
                            case "getName": return locator.getName();
                            case "getProjectLocator": return locator;
                            default: throw new AssertionError("Unexpected native project access: " + method);
                        }
                    });
                Class<?> api = Class.forName("ghidra.app.plugin.core.archive.ArchiveTask", true, loader);
                Constructor<?> ctor = api.getDeclaredConstructor(Project.class, File.class);
                ctor.setAccessible(true);
                ((Task) ctor.newInstance(project, archive)).run(monitor);
                if (!archive.isFile()) throw new AssertionError("Native archive failed");
            } finally { lock.release(); }
        } else {
            // Run the native validator/extractor/marker creation; omit only the
            // final FrontEndTool GUI activation. Actual databases are opened by
            // VerifyArchiveFixture afterwards.
            Class<?> api = Class.forName("ghidra.app.plugin.core.archive.RestoreTask", true, loader);
            Class<?> plugin = Class.forName("ghidra.app.plugin.core.archive.ArchivePlugin", true, loader);
            Constructor<?> ctor = api.getDeclaredConstructor(ProjectLocator.class, File.class, plugin);
            ctor.setAccessible(true);
            var locator = new ProjectLocator(path.getParent().toString(), path.getFileName().toString());
            Object task = ctor.newInstance(locator, archive, null);
            var service = FileSystemService.getInstance();
            try (GFileSystem fs = service.openFileSystemContainer(service.getLocalFSRL(archive), monitor)) {
                Method verify = api.getDeclaredMethod("verifyArchive", GFileSystem.class, TaskMonitor.class);
                verify.setAccessible(true);
                verify.invoke(task, fs, monitor);
                Method extract = AbstractFileExtractorTask.class.getDeclaredMethod("startExtract",
                    GFileSystem.class, GFile.class, TaskMonitor.class);
                extract.setAccessible(true);
                extract.invoke(task, fs, null, monitor);
                Method marker = api.getDeclaredMethod("createProjectMarkerFile");
                marker.setAccessible(true);
                marker.invoke(task);
            }
        }
    }
}
