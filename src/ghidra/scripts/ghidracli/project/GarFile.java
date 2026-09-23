package ghidracli.project;

import ghidra.util.task.TaskMonitor;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.*;
import java.util.jar.JarOutputStream;
import java.util.zip.*;

/** Ghidra ArchiveTask/RestoreTask's JAR_FORMAT layout, without GUI task ownership. */
final class GarFile {
    private GarFile() {}

    // Upstream: Features/Base/.../archive/{ArchiveTask,RestoreTask,ArchivePlugin}.java.
    // A GAR has the .gpr marker and JAR_FORMAT at its root, followed by the
    // contents of .rep's subdirectories (not a wrapping <name>.rep directory).
    static void write(Path project, String projectName, Path output, TaskMonitor monitor) throws Exception {
        try (JarOutputStream zip = new JarOutputStream(Files.newOutputStream(output,
                StandardOpenOption.CREATE_NEW))) {
            zip.setComment("Ghidra archive file for " + projectName + " project.");
            zip.putNextEntry(new ZipEntry(projectName + ".gpr"));
            zip.closeEntry();
            zip.putNextEntry(new ZipEntry("JAR_FORMAT"));
            zip.closeEntry();
            Path data = Path.of(project + ".rep");
            visit(data, monitor, (path, directory) -> {
                String name = data.relativize(path).toString().replace(java.io.File.separatorChar, '/');
                if (name.endsWith(".ulock")) return;
                ZipEntry entry = new ZipEntry(name + (directory ? "/" : ""));
                entry.setTime(Files.getLastModifiedTime(path).toMillis());
                zip.putNextEntry(entry);
                if (!directory) {
                    try (InputStream input = Files.newInputStream(path)) {
                        transfer(input, zip, monitor, null);
                    }
                }
                zip.closeEntry();
            });
        }
    }

    static void copyProject(Path sourceData, Path destinationData, TaskMonitor monitor) throws Exception {
        Files.createDirectory(destinationData);
        visit(sourceData, monitor, (path, directory) -> {
            if (path.getFileName().toString().endsWith(".ulock")) return;
            Path target = destinationData.resolve(sourceData.relativize(path));
            if (directory) Files.createDirectory(target);
            else {
                try (InputStream in = Files.newInputStream(path);
                        OutputStream out = Files.newOutputStream(target, StandardOpenOption.CREATE_NEW)) {
                    transfer(in, out, monitor, null);
                }
            }
        });
    }

    private interface Visitor { void accept(Path path, boolean directory) throws Exception; }

    // Only .rep subdirectories are in standard GARs. Root project.prp and
    // projectState are intentionally excluded. Never follow filesystem symlinks.
    private static void visit(Path data, TaskMonitor monitor, Visitor visitor) throws Exception {
        try (var roots = Files.newDirectoryStream(data)) {
            for (Path root : roots) {
                if (Files.isSymbolicLink(root)) throw new IOException("Symbolic link in project: " + root);
                if (!Files.isDirectory(root, LinkOption.NOFOLLOW_LINKS)) continue;
                try (var paths = Files.walk(root)) {
                    for (Path path : (Iterable<Path>) paths::iterator) {
                        monitor.checkCancelled();
                        BasicFileAttributes attrs = Files.readAttributes(path, BasicFileAttributes.class,
                            LinkOption.NOFOLLOW_LINKS);
                        if (!attrs.isDirectory() && !attrs.isRegularFile()) {
                            throw new IOException("Non-regular project entry: " + path);
                        }
                        visitor.accept(path, attrs.isDirectory());
                    }
                }
            }
        }
    }

    static void extract(Path archive, Path data, TaskMonitor monitor) throws Exception {
        try (ZipFile zip = new ZipFile(archive.toFile())) {
            ZipEntry marker = zip.getEntry("JAR_FORMAT");
            if (marker == null || marker.isDirectory() || marker.getSize() != 0) {
                throw new IOException("Missing or invalid Ghidra GAR JAR_FORMAT marker");
            }
            Set<String> names = new HashSet<>();
            List<? extends ZipEntry> entries = Collections.list(zip.entries());
            // Validate the entire namespace before extracting, including entries
            // that Ghidra excludes. Duplicate entries must never choose a winner.
            for (ZipEntry entry : entries) {
                monitor.checkCancelled();
                String name = validateName(entry);
                if (!names.add(name)) throw new IOException("Duplicate GAR entry: " + name);
            }
            Files.createDirectory(data);
            Map<Path, String> directories = new HashMap<>();
            for (ZipEntry entry : entries) {
                monitor.checkCancelled();
                String name = validateName(entry);
                boolean skipped = excluded(name);
                Path destination = data.resolve(name);
                if (!destination.normalize().startsWith(data)) throw new IOException("Unsafe GAR path: " + name);
                if (entry.isDirectory()) {
                    if (!skipped) directory(data, destination, directories);
                    continue;
                }
                if (!skipped) directory(data, destination.getParent(), directories);
                CRC32 crc = new CRC32();
                long size;
                try (InputStream in = zip.getInputStream(entry);
                        OutputStream out = skipped ? OutputStream.nullOutputStream()
                            : Files.newOutputStream(destination, StandardOpenOption.CREATE_NEW)) {
                    size = transfer(in, out, monitor, crc);
                }
                if (size != entry.getSize() || crc.getValue() != entry.getCrc()) {
                    throw new IOException("Corrupt GAR entry: " + name);
                }
            }
        }
        if (!Files.isDirectory(data.resolve("idata")) && !Files.isDirectory(data.resolve("data"))) {
            throw new IOException("GAR has no Ghidra project database");
        }
    }

    private static String validateName(ZipEntry entry) throws IOException {
        // Ghidra's JarWriter uses File.separator, including backslashes on Windows.
        // Canonicalize before validation, duplicate detection, exclusions and extraction.
        String name = entry.getName().replace('\\', '/');
        if (entry.isDirectory()) name = name.substring(0, name.length() - 1);
        if (name.isEmpty() || name.indexOf(':') >= 0 || name.indexOf('\0') >= 0) {
            throw new IOException("Unsafe GAR entry: " + entry.getName());
        }
        for (String part : name.split("/", -1)) {
            if (part.isEmpty() || part.equals(".") || part.equals("..")) {
                throw new IOException("Unsafe GAR entry: " + entry.getName());
            }
            // Win32 device names and trimmed path components can address a
            // device or alias another entry even below a checked destination.
            if (java.io.File.separatorChar == '\\') {
                String base = part.split("\\.", 2)[0].toUpperCase(Locale.ROOT);
                if (part.endsWith(".") || part.endsWith(" ")
                        || Set.of("CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$").contains(base)
                        || base.matches("(?:COM|LPT)[1-9¹²³]")) {
                    throw new IOException("Unsafe GAR entry on Windows: " + entry.getName());
                }
            }
        }
        return name;
    }

    private static boolean excluded(String name) {
        String lower = name.toLowerCase(Locale.ROOT);
        String root = lower.split("/", 2)[0];
        String base = lower.substring(lower.lastIndexOf('/') + 1);
        return Set.of("jar_format", "project.prp", "projectstate", "save", "groups").contains(root)
            || base.equals(".properties") || base.endsWith(".gpr") || base.endsWith(".ulock");
    }

    private static void directory(Path root, Path path, Map<Path, String> seen) throws IOException {
        if (path.equals(root)) return;
        directory(root, path.getParent(), seen);
        String name = root.relativize(path).toString();
        if (!Files.exists(path, LinkOption.NOFOLLOW_LINKS)) Files.createDirectory(path);
        if (!Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)) throw new IOException("GAR file/directory collision: " + name);
        String previous = seen.putIfAbsent(path.toRealPath(), name);
        if (previous != null && !previous.equals(name)) {
            throw new IOException("GAR directory aliases collide: " + previous + " and " + name);
        }
    }

    private static long transfer(InputStream in, OutputStream out, TaskMonitor monitor, CRC32 crc)
            throws Exception {
        byte[] buffer = new byte[65536];
        long total = 0;
        int count;
        while ((count = in.read(buffer)) != -1) {
            monitor.checkCancelled();
            out.write(buffer, 0, count);
            if (crc != null) crc.update(buffer, 0, count);
            total += count;
        }
        return total;
    }

    static void removeTree(Path path) throws IOException {
        if (!Files.exists(path, LinkOption.NOFOLLOW_LINKS)) return;
        Files.walkFileTree(path, new SimpleFileVisitor<Path>() {
            @Override public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
                Files.delete(file);
                return FileVisitResult.CONTINUE;
            }
            @Override public FileVisitResult postVisitDirectory(Path dir, IOException error) throws IOException {
                if (error != null) throw error;
                Files.delete(dir);
                return FileVisitResult.CONTINUE;
            }
        });
    }
}
