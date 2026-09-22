package ghidracli;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import generic.util.FileLocker;
import generic.util.LockFactory;
import ghidra.framework.data.DefaultProjectData;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.ProjectLocator;
import ghidra.util.task.TaskMonitor;
import java.io.IOException;
import java.lang.reflect.Method;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.Properties;

/** One-shot GAR operations on closed projects, under Ghidra's project lock. */
public final class ProjectArchive {
    private final JsonObject detail = new JsonObject();
    private final TaskMonitor monitor;
    private Path staging;
    private Path outputStaging;
    private Path workspace;
    private Path ownedData;
    private boolean published;

    private ProjectArchive(TaskMonitor monitor) { this.monitor = monitor; }

    public static JsonObject run(JsonObject args, TaskMonitor monitor) throws Exception {
        return new ProjectArchive(monitor).execute(args);
    }

    private JsonObject execute(JsonObject args) throws Exception {
        String operation = args.get("archive_operation").getAsString();
        Path project = Path.of(args.get("project_path").getAsString()).toAbsolutePath().normalize();
        Path file = Path.of(args.get("file").getAsString()).toAbsolutePath().normalize();
        workspace = Path.of(args.get("workspace").getAsString());
        detail.addProperty("operation", operation);
        detail.addProperty("project_path", project.toString());
        detail.addProperty(operation.equals("archive") ? "output" : "archive", file.toString());
        FileLocker lock = null;
        JsonObject result = null;
        Exception failure = null;
        try {
            stage("preflight");
            if (!operation.equals("archive") && !operation.equals("restore")) {
                throw new IOException("Unknown GAR operation: " + operation);
            }
            ProjectLocator locator = locator(project);
            Path data = locator.getProjectDir().toPath();
            Path marker = locator.getMarkerFile().toPath();
            if (operation.equals("archive")) {
                absent(file);
                if (!Files.isRegularFile(marker) || !Files.isDirectory(data)) {
                    throw new IOException("Project requires both .gpr and .rep: " + project);
                }
                BasicFileAttributes attributes = Files.readAttributes(data, BasicFileAttributes.class,
                    LinkOption.NOFOLLOW_LINKS);
                if (attributes.isSymbolicLink() || attributes.isOther()) {
                    throw new IOException("Project .rep is a filesystem link; use the real project base path so Ghidra's lock protects its data");
                }
                if (file.getParent().toRealPath().startsWith(data.toRealPath())) {
                    throw new IOException("Archive output must be outside the project's .rep directory");
                }
            } else {
                absent(data);
                absent(marker);
                Files.createDirectories(project.getParent());
            }
            stage("lock");
            lock = LockFactory.createFileLocker(locator.getProjectLockFile());
            if (!lock.lock()) {
                lock = null; // Never release a lock belonging to an external Ghidra.
                throw new IOException("Project is locked by another Ghidra process");
            }
            monitor.checkCancelled();
            if (operation.equals("archive")) result = archive(project, data, file);
            else result = restore(project, data, marker, file);
        } catch (Exception error) {
            failure = error;
        } finally {
            JsonArray remaining = new JsonArray();
            for (Path path : new Path[] { published ? null : ownedData, staging, outputStaging }) {
                if (path == null) continue;
                try { GarFile.removeTree(path); }
                catch (IOException error) {
                    remaining.add(path.toString());
                    if (failure == null) failure = error;
                    else failure.addSuppressed(error);
                }
            }
            if (!remaining.isEmpty()) detail.add("remaining_paths", remaining);
            if (lock != null) lock.release();
        }
        if (failure != null) {
            detail.addProperty("published", published);
            detail.addProperty("cancelled", monitor.isCancelled());
            detail.addProperty("cause", failure.toString());
            throw new JsonProtocol.CommandException("Project " + operation + " failed: "
                + failure.getMessage(), detail);
        }
        return result;
    }

    private JsonObject archive(Path project, Path data, Path output) throws Exception {
        stage("snapshot");
        // Ghidra rejects dot-prefixed project path components. An archive may
        // legitimately live in .backups; inspect under the bootstrap workspace
        // and put only the final packed staging file beside the destination.
        staging = Files.createTempDirectory(workspace, "ghidra-cli-gar-");
        Path snapshot = staging.resolve("snapshot");
        Path snapshotData = Path.of(snapshot + ".rep");
        GarFile.copyProject(data, snapshotData, monitor);
        Files.createFile(Path.of(snapshot + ".gpr"));
        JsonObject result = inspect(snapshot);
        // Read repository identity without connecting to a remote server. GAR
        // contains only local storage; the staged project has no server binding.
        Properties props = DefaultProjectData.readProjectProperties(data.toFile());
        if (props == null && Files.exists(data.resolve("project.prp"))) {
            throw new IOException("Cannot read source project properties: " + data);
        }
        JsonObject repository = null;
        if (props != null && props.getProperty(DefaultProjectData.SERVER_NAME) != null) {
            repository = new JsonObject();
            repository.addProperty("server", props.getProperty(DefaultProjectData.SERVER_NAME));
            repository.addProperty("name", props.getProperty(DefaultProjectData.REPOSITORY_NAME));
            repository.addProperty("port", props.getProperty(DefaultProjectData.PORT_NUMBER));
        }
        result.add("source_repository", repository);
        stage("write");
        outputStaging = Files.createTempDirectory(output.getParent(), "ghidra-cli-gar-output-");
        Path packed = outputStaging.resolve("archive.gar");
        GarFile.write(snapshot, project.getFileName().toString(), packed, monitor);
        monitor.checkCancelled();
        stage("publish");
        // A hard-link publishes a complete sibling file atomically and fails if
        // any destination already exists. Files.move(ATOMIC_MOVE) can overwrite.
        Files.createLink(output, packed);
        published = true;
        result.addProperty("output", output.toString());
        result.addProperty("size_bytes", Files.size(output));
        result.addProperty("snapshot", "saved_local_contents");
        return receipt(result, project);
    }

    private JsonObject restore(Path project, Path data, Path marker, Path archive) throws Exception {
        stage("extract");
        staging = Files.createTempDirectory(project.getParent(), "ghidra-cli-restore-");
        Path snapshot = staging.resolve("snapshot");
        Path snapshotData = Path.of(snapshot + ".rep");
        GarFile.extract(archive, snapshotData, monitor);
        Files.createFile(Path.of(snapshot + ".gpr"));
        stage("validate");
        JsonObject result = inspect(snapshot);
        monitor.checkCancelled();
        stage("publish");
        absent(marker);
        // Claim the directory exclusively; a no-options Files.move can race an
        // existing destination on Unix. Publish the .gpr only after all data.
        Files.createDirectory(data);
        ownedData = data;
        try (var children = Files.newDirectoryStream(snapshotData)) {
            for (Path child : children) {
                monitor.checkCancelled();
                Files.move(child, data.resolve(child.getFileName()));
            }
        }
        monitor.checkCancelled();
        Files.createFile(marker);
        published = true;
        result.addProperty("archive", archive.toString());
        return receipt(result, project);
    }

    private JsonObject inspect(Path project) throws Exception {
        stage("validate");
        // Validate and inspect the private copy only. Opening never mutates the
        // source and never connects its shared-repository configuration.
        DefaultProjectData data = new DefaultProjectData(locator(project), true, true);
        JsonObject result = new JsonObject();
        JsonArray links = new JsonArray();
        int[] counts = new int[2];
        boolean[] complete = {true};
        try { inspectFolder(data.getRootFolder(), links, counts, complete); }
        finally { data.close(); }
        result.addProperty("files", counts[0]);
        result.addProperty("folders", counts[1]);
        JsonObject dependencies = new JsonObject();
        dependencies.addProperty("scope", "project_links");
        dependencies.addProperty("complete", complete[0]);
        dependencies.add("links", links);
        JsonArray unexamined = new JsonArray();
        unexamined.add("External paths in Program options, source maps, and file type archives are not scanned or bundled.");
        dependencies.add("limitations", unexamined);
        result.add("external_dependencies", dependencies);
        return result;
    }

    private void inspectFolder(DomainFolder folder, JsonArray links, int[] counts, boolean[] complete)
            throws Exception {
        for (DomainFile file : folder.getFiles()) {
            monitor.checkCancelled();
            counts[0]++;
            // Link APIs changed in Ghidra 12.1. Reflect only that boundary so
            // older supported installations still compile and report uncertainty.
            try {
                Method isLink;
                try { isLink = DomainFile.class.getMethod("isLink"); }
                catch (NoSuchMethodException olderGhidra) {
                    isLink = DomainFile.class.getMethod("isLinkFile");
                }
                if (!Boolean.TRUE.equals(isLink.invoke(file))) continue;
                JsonObject link = new JsonObject();
                link.addProperty("path", file.getPathname());
                link.addProperty("content_type", file.getContentType());
                try {
                    Object info = DomainFile.class.getMethod("getLinkInfo").invoke(file);
                    Class<?> api = Class.forName("ghidra.framework.model.LinkFileInfo", true,
                        DomainFile.class.getClassLoader());
                    link.addProperty("target", (String) api.getMethod("getLinkPath").invoke(info));
                    link.addProperty("direct_external", (Boolean) api.getMethod("isExternalLink").invoke(info));
                } catch (NoSuchMethodException | ClassNotFoundException olderGhidra) {
                    try {
                        Class<?> api = Class.forName("ghidra.framework.data.LinkHandler", true,
                            DomainFile.class.getClassLoader());
                        Object url = api.getMethod("getURL", DomainFile.class).invoke(null, file);
                        link.addProperty("target", url.toString());
                        link.addProperty("direct_external", true);
                    } catch (NoSuchMethodException | ClassNotFoundException unavailable) {
                        complete[0] = false;
                        link.add("target", null);
                        link.add("direct_external", null);
                    }
                }
                links.add(link);
            } catch (NoSuchMethodException error) {
                complete[0] = false;
            }
        }
        for (DomainFolder child : folder.getFolders()) {
            monitor.checkCancelled();
            // Real project folders only; never traverse a linked target.
            counts[1]++;
            inspectFolder(child, links, counts, complete);
        }
    }

    private static ProjectLocator locator(Path project) throws IOException {
        ProjectLocator locator = new ProjectLocator(project.getParent().toString(), project.getFileName().toString());
        if (!locator.getName().equals(project.getFileName().toString())) {
            throw new IOException("Use a project base path without the .gpr suffix: " + project);
        }
        return locator;
    }

    private static void absent(Path path) throws IOException {
        if (Files.exists(path, LinkOption.NOFOLLOW_LINKS)) throw new FileAlreadyExistsException(path.toString());
    }

    private void stage(String name) { detail.addProperty("stage", "project." + detail.get("operation").getAsString() + "_" + name); }

    private JsonObject receipt(JsonObject result, Path project) {
        result.addProperty("status", "success");
        result.addProperty("format", "gar");
        result.addProperty("project_path", project.toString());
        result.addProperty("bridge_state", "stopped");
        return result;
    }
}
