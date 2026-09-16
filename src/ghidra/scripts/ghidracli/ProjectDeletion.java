package ghidracli;

import com.google.gson.JsonObject;
import generic.util.FileLocker;
import generic.util.LockFactory;
import ghidra.framework.model.ProjectLocator;
import java.io.File;
import java.io.IOException;
import java.nio.file.DirectoryNotEmptyException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.FileVisitResult;
import java.nio.file.attribute.BasicFileAttributes;

/** Delete a closed project while holding the same lock as Ghidra's project manager. */
public final class ProjectDeletion {
    private ProjectDeletion() {}

    public static JsonObject run(String projectPath) throws Exception {
        File project = new File(projectPath).getAbsoluteFile();
        ProjectLocator locator = new ProjectLocator(project.getParent(), project.getName());
        FileLocker lock = LockFactory.createFileLocker(locator.getProjectLockFile());
        if (!lock.lock()) {
            JsonObject detail = new JsonObject();
            detail.addProperty("stage", "project.delete_lock");
            detail.addProperty("path", projectPath);
            throw new JsonProtocol.CommandException(
                "Project is locked by another Ghidra process; no project files were deleted", detail);
        }
        try {
            Path data = locator.getProjectDir().toPath();
            Path descriptor = locator.getMarkerFile().toPath();
            boolean deleted = Files.exists(data) || Files.exists(descriptor);
            if (Files.exists(data)) {
                // Do not follow symlinks to unrelated directories.
                Files.walkFileTree(data, new SimpleFileVisitor<Path>() {
                    @Override
                    public FileVisitResult visitFile(Path file, BasicFileAttributes attributes)
                            throws IOException {
                        Files.delete(file);
                        return FileVisitResult.CONTINUE;
                    }
                    @Override
                    public FileVisitResult postVisitDirectory(Path directory, IOException error)
                            throws IOException {
                        if (error != null) throw error;
                        Files.delete(directory);
                        return FileVisitResult.CONTINUE;
                    }
                });
            }
            Files.deleteIfExists(descriptor);
            // Older create_project only reserved an empty bare directory.
            if (project.isDirectory()) {
                try {
                    deleted |= Files.deleteIfExists(project.toPath());
                } catch (DirectoryNotEmptyException ignored) {
                    // Preserve files users placed outside the .gpr/.rep artifacts.
                }
            }
            JsonObject result = new JsonObject();
            result.addProperty("status", "success");
            result.addProperty("deleted", deleted);
            return result;
        } finally {
            lock.release();
        }
    }
}
