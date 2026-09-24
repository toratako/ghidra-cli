package ghidracli.types;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import db.DBHandle;
import ghidra.framework.data.OpenMode;
import ghidra.framework.model.RuntimeIOException;
import ghidra.framework.store.db.PackedDatabase;
import ghidra.program.model.data.ArchiveType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.FileDataTypeManager;
import ghidra.program.model.data.StandAloneDataTypeManager;
import ghidra.util.Lock;
import ghidra.util.task.TaskMonitor;
import ghidracli.protocol.JsonProtocol;
import ghidracli.session.ProgramSession;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;

import static ghidracli.protocol.JsonProtocol.errorResult;
import static ghidracli.protocol.JsonProtocol.getArgString;
import static ghidracli.protocol.JsonProtocol.getNonnegativeIntArg;

/** Native file data-type archives, with guarded selection and no-clobber export. */
public final class TypeArchiveCommands {
    private final ProgramSession session;

    public TypeArchiveCommands(ProgramSession session) { this.session = session; }

    public JsonObject handleList(JsonObject args) {
        try {
            Path file = input(args);
            try (ArchiveRead read = snapshot(file)) {
                StandAloneDataTypeManager archive = read.archive;
                List<DataType> candidates = TypeArchiveGraph.candidates(archive, session.monitor());
                int offset = getNonnegativeIntArg(args, "offset", 0);
                int limit = getNonnegativeIntArg(args, "limit", 0);
                JsonArray rows = new JsonArray();
                for (int i = Math.min(offset, candidates.size()); i < candidates.size(); i++) {
                    session.monitor().checkCancelled();
                    if (limit != 0 && rows.size() >= limit) break;
                    rows.add(TypeArchiveGraph.describe(candidates.get(i)));
                }
                requireUnchanged(file, read.fingerprint);
                JsonObject result = new JsonObject();
                result.add("types", rows);
                result.add("archive", archiveInfo(archive, file));
                result.addProperty("count", rows.size());
                return result;
            }
        } catch (Exception error) {
            return errorResult("Failed to list type archive: " + error.getMessage(), error);
        }
    }

    public JsonObject handleCandidates(JsonObject args) {
        try {
            if (getArgString(args, "file") == null) {
                requireProgram();
                JsonObject guard = programGuard();
                JsonObject result = candidates(session.program().getDataTypeManager());
                requireGuard(guard, programGuard());
                result.add("source", guard);
                return result;
            }
            Path file = input(args);
            try (ArchiveRead read = snapshot(file)) {
                StandAloneDataTypeManager archive = read.archive;
                JsonObject result = candidates(archive);
                requireUnchanged(file, read.fingerprint);
                result.add("source", archiveGuard(archive, file, read.fingerprint));
                return result;
            }
        } catch (Exception error) {
            return errorResult("Failed to enumerate archive candidates: " + error.getMessage(), error);
        }
    }

    public JsonObject handleImport(JsonObject args) {
        try {
            requireProgram();
            Path file = input(args);
            try (ArchiveRead read = snapshot(file)) {
                StandAloneDataTypeManager archive = read.archive;
                JsonObject guard = archiveGuard(archive, file, read.fingerprint);
                List<DataType> roots = selected(args, archive, guard);
                TypeArchiveGraph graph = new TypeArchiveGraph(roots, session.monitor());
                long modification = session.program().getModificationNumber();
                JsonObject result = graph.transfer(session.program().getDataTypeManager(), session.monitor());
                requireUnchanged(file, read.fingerprint);
                session.monitor().checkCancelled();
                result.addProperty("status", "imported");
                result.addProperty("changed", modification != session.program().getModificationNumber());
                result.add("source", guard);
                result.add("archive", archiveInfo(archive, file));
                return result;
            }
        } catch (Exception error) {
            return errorResult("Failed to import type archive: " + error.getMessage(), error);
        }
    }

    public JsonObject handleExport(JsonObject args) {
        Path staging = null;
        Path output = null;
        boolean published = false;
        JsonObject result = null;
        JsonObject detail = new JsonObject();
        Exception failure = null;
        try {
            requireProgram();
            output = output(args);
            detail.addProperty("output", output.toString());
            JsonObject guard = programGuard();
            List<DataType> roots = selected(args, session.program().getDataTypeManager(), guard);
            TypeArchiveGraph graph = new TypeArchiveGraph(roots, session.monitor());
            staging = Files.createTempDirectory(output.getParent(), "ghidra-cli-gdt-");
            Path packed = staging.resolve(output.getFileName());
            session.monitor().checkCancelled();
            try (FileDataTypeManager archive = FileDataTypeManager.createFileArchive(packed.toFile(),
                    session.program().getLanguageID(),
                    session.program().getCompilerSpec().getCompilerSpecID())) {
                checkWarning(archive);
                int transaction = archive.startTransaction("Export selected type definitions");
                boolean commit = false;
                try {
                    result = graph.transfer(archive, session.monitor());
                    commit = true;
                } finally {
                    if (!archive.endTransaction(transaction, commit) && commit)
                        throw new IOException("Ghidra aborted the archive transaction");
                }
                session.monitor().checkCancelled();
                archive.save();
            }
            // Saving can normalize records: verify the actual persisted archive.
            try (StandAloneDataTypeManager archive = open(packed)) {
                graph.verify(archive, session.monitor());
                result.add("archive", archiveInfo(archive, output));
            }
            requireGuard(guard, programGuard());
            result.add("source", guard);
            result.addProperty("status", "exported");
            result.addProperty("output", output.toString());
            result.addProperty("size_bytes", Files.size(packed));
            result.addProperty("sha256", digest(packed));
            session.monitor().checkCancelled();
            // A sibling hard-link publishes atomically and never replaces a
            // competing writer's path. Unsupported filesystems fail explicitly.
            Files.createLink(output, packed);
            published = true;
        } catch (Exception error) {
            failure = error;
        } finally {
            if (staging != null) {
                try { removeStaging(staging); }
                catch (Exception cleanup) {
                    if (failure == null) failure = cleanup;
                    else failure.addSuppressed(cleanup);
                    JsonArray remaining = new JsonArray();
                    remaining.add(staging.toString());
                    detail.add("remaining_paths", remaining);
                }
            }
        }
        if (failure != null) {
            detail.addProperty("published", published);
            detail.addProperty("cancelled", session.monitor().isCancelled());
            detail.addProperty("cause", failure.toString());
            if (published && output != null) {
                JsonArray paths = new JsonArray();
                paths.add(output.toString());
                detail.add("published_paths", paths);
            }
            String message = published
                ? "Type archive was exported to " + output + ", but staging cleanup failed: " + failure.getMessage()
                : "Failed to export type archive: " + failure.getMessage();
            return errorResult(message,
                new JsonProtocol.CommandException(failure.getMessage(), detail));
        }
        return result;
    }

    private JsonObject candidates(DataTypeManager manager) throws Exception {
        JsonArray rows = new JsonArray();
        for (DataType type : TypeArchiveGraph.candidates(manager, session.monitor()))
            rows.add(TypeArchiveGraph.describe(type));
        JsonObject result = new JsonObject();
        result.add("types", rows);
        return result;
    }

    private List<DataType> selected(JsonObject args, DataTypeManager manager, JsonObject guard) throws Exception {
        boolean hasAll = args.has("all");
        boolean hasPaths = args.has("paths");
        if (hasAll == hasPaths)
            throw new IllegalArgumentException("Select exactly one of all or paths");
        if (hasAll) {
            JsonElement all = args.get("all");
            if (!all.isJsonPrimitive() || !all.getAsJsonPrimitive().isBoolean() || !all.getAsBoolean()
                    || args.has("source"))
                throw new IllegalArgumentException("all must be true and cannot include a source selection guard");
            List<DataType> result = TypeArchiveGraph.candidates(manager, session.monitor());
            if (result.isEmpty()) throw new IllegalArgumentException("No named type definitions selected");
            return result;
        }
        if (!args.get("paths").isJsonArray() || args.getAsJsonArray("paths").isEmpty())
            throw new IllegalArgumentException("Selected type paths must be a non-empty array");
        if (!args.has("source") || !args.get("source").isJsonObject())
            throw new IllegalArgumentException("Selected paths require their source guard");
        requireGuard(args.getAsJsonObject("source"), guard);
        SortedMap<String, DataType> selected = new TreeMap<>();
        for (JsonElement value : args.getAsJsonArray("paths")) {
            session.monitor().checkCancelled();
            if (!value.isJsonPrimitive() || !value.getAsJsonPrimitive().isString())
                throw new IllegalArgumentException("Selected type paths must be strings");
            String path = value.getAsString();
            DataType type = manager.getDataType(path);
            if (!path.startsWith("/") || type == null || !path.equals(type.getPathName())
                    || !TypeArchiveGraph.selectable(type))
                throw new IllegalArgumentException("Selected named definition does not exist at exact path: " + path);
            if (selected.put(path, type) != null)
                throw new IllegalArgumentException("Duplicate selected type path: " + path);
        }
        return new ArrayList<>(selected.values());
    }

    private JsonObject programGuard() {
        JsonObject result = new JsonObject();
        result.addProperty("kind", "program");
        result.addProperty("program", session.programPath());
        result.addProperty("archive_id", session.program().getDataTypeManager().getUniversalID().toString());
        result.addProperty("modification_number", session.program().getModificationNumber());
        return result;
    }

    private static JsonObject archiveGuard(DataTypeManager archive, Path file, String fingerprint) {
        JsonObject result = new JsonObject();
        result.addProperty("kind", "gdt");
        result.addProperty("path", file.toString());
        result.addProperty("sha256", fingerprint);
        result.addProperty("archive_id", archive.getUniversalID().toString());
        return result;
    }

    private static void requireGuard(JsonObject expected, JsonObject actual) {
        if (!expected.equals(actual))
            throw new IllegalArgumentException("Type selection source changed; select the types again");
    }

    private JsonObject archiveInfo(DataTypeManager archive, Path file) {
        JsonObject result = new JsonObject();
        result.addProperty("path", file.toString());
        result.addProperty("id", archive.getUniversalID().toString());
        result.addProperty("name", archive.getName());
        var architecture = archive.getProgramArchitecture();
        result.addProperty("language", architecture == null ? null : architecture.getLanguage().getLanguageID().toString());
        result.addProperty("compiler", architecture == null ? null : architecture.getCompilerSpec().getCompilerSpecID().toString());
        result.addProperty("pointer_size", archive.getDataOrganization().getPointerSize());
        result.addProperty("big_endian", archive.getDataOrganization().isBigEndian());
        return result;
    }

    private StandAloneDataTypeManager open(Path file) throws Exception {
        session.monitor().checkCancelled();
        // The regular FileDataTypeManager factory caches every unique input path
        // across requests. These short-lived snapshots must own their unpacked
        // database so closing also removes it from the native temporary storage.
        PackedDatabase packed = PackedDatabase.getPackedDatabase(file.toFile(), true, session.monitor());
        DBHandle handle = null;
        StandAloneDataTypeManager archive = null;
        try {
            handle = packed.open(session.monitor());
            archive = new ArchiveManager(handle, file, session.monitor());
            checkWarning(archive);
            session.monitor().checkCancelled();
            return archive;
        } catch (Exception failure) {
            try {
                if (archive != null) archive.close();
                else if (handle != null) handle.close();
            } catch (Exception cleanup) { failure.addSuppressed(cleanup); }
            try { packed.dispose(); }
            catch (Exception cleanup) { failure.addSuppressed(cleanup); }
            throw failure;
        }
    }

    /** Immutable native archive semantics over an explicitly uncached handle. */
    private static final class ArchiveManager extends StandAloneDataTypeManager {
        private final Path file;

        ArchiveManager(DBHandle handle, Path file, TaskMonitor monitor) throws Exception {
            super(handle, OpenMode.IMMUTABLE, error -> { throw new RuntimeIOException(error); },
                new Lock("GDT archive read"), monitor);
            this.file = file;
            String filename = file.getFileName().toString();
            name = filename.substring(0, filename.length() - ".gdt".length());
            setImmutable();
        }

        @Override
        public ArchiveType getType() { return ArchiveType.FILE; }

        @Override
        public String getPath() { return file.toString(); }
    }

    private ArchiveRead snapshot(Path file) throws Exception {
        Path workspace = Files.createTempDirectory("ghidra-cli-gdt-read-");
        StandAloneDataTypeManager archive = null;
        try {
            // Rust validates the supplied .gdt name before resolving symlinks.
            // The target may have another suffix, while ArchiveManager requires
            // its private snapshot to end in .gdt for the displayed name.
            String filename = file.getFileName().toString();
            Path copy = workspace.resolve(filename.endsWith(".gdt") ? filename : filename + ".gdt");
            byte[] buffer = new byte[64 * 1024];
            // PackedDatabase caches source paths by mtime. A unique copy binds
            // the parsed graph to these exact bytes even after an archive was
            // replaced in place while preserving its timestamp.
            try (InputStream input = Files.newInputStream(file);
                    OutputStream output = Files.newOutputStream(copy, StandardOpenOption.CREATE_NEW)) {
                int count;
                while ((count = input.read(buffer)) >= 0) {
                    session.monitor().checkCancelled();
                    output.write(buffer, 0, count);
                }
            }
            String fingerprint = digest(copy);
            requireUnchanged(file, fingerprint);
            archive = open(copy);
            return new ArchiveRead(workspace, archive, fingerprint);
        } catch (Exception failure) {
            if (archive != null) archive.close();
            try { removeStaging(workspace); }
            catch (Exception cleanup) {
                throw snapshotCleanupFailure(workspace, failure, cleanup);
            }
            throw failure;
        }
    }

    private static JsonProtocol.CommandException snapshotCleanupFailure(Path workspace,
            Exception failure, Exception cleanup) {
        JsonObject detail = new JsonObject();
        JsonArray remaining = new JsonArray();
        remaining.add(workspace.toString());
        detail.add("remaining_paths", remaining);
        detail.addProperty("cause", failure.toString());
        detail.addProperty("cleanup_error", cleanup.toString());
        return new JsonProtocol.CommandException("Archive snapshot cleanup failed: "
            + workspace + ": " + failure.getMessage(), detail);
    }

    private static final class ArchiveRead implements AutoCloseable {
        final Path workspace;
        final StandAloneDataTypeManager archive;
        final String fingerprint;

        ArchiveRead(Path workspace, StandAloneDataTypeManager archive, String fingerprint) {
            this.workspace = workspace;
            this.archive = archive;
            this.fingerprint = fingerprint;
        }

        @Override
        public void close() throws IOException {
            try { archive.close(); }
            finally {
                try { removeStaging(workspace); }
                catch (IOException cleanup) {
                    throw snapshotCleanupFailure(workspace, cleanup, cleanup);
                }
            }
        }
    }

    private static void checkWarning(StandAloneDataTypeManager archive) throws IOException {
        if (archive.getWarning() != StandAloneDataTypeManager.ArchiveWarning.NONE)
            throw new IOException("Archive architecture warning: " + archive.getWarningMessage(false));
    }

    private void requireProgram() {
        if (session.program() == null) throw new IllegalArgumentException("No program loaded");
    }

    private static Path suppliedPath(JsonObject args) {
        String value = getArgString(args, "file");
        if (value == null || value.isBlank()) throw new IllegalArgumentException("Archive file required");
        Path path = Path.of(value);
        if (!path.isAbsolute()) throw new IllegalArgumentException("Archive file must be an absolute path");
        return path;
    }

    private static Path input(JsonObject args) throws IOException {
        Path path = suppliedPath(args).toRealPath();
        if (!Files.isRegularFile(path)) throw new IOException("Archive is not a regular file: " + path);
        return path;
    }

    private static Path output(JsonObject args) throws IOException {
        Path path = suppliedPath(args);
        if (!path.getFileName().toString().endsWith(".gdt"))
            throw new IllegalArgumentException("Archive file must have a .gdt suffix");
        Path resolved = path.getParent().toRealPath().resolve(path.getFileName());
        if (Files.exists(resolved, LinkOption.NOFOLLOW_LINKS))
            throw new FileAlreadyExistsException("Output archive already exists: " + resolved);
        return resolved;
    }

    private String digest(Path file) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] buffer = new byte[64 * 1024];
        try (InputStream input = Files.newInputStream(file)) {
            int count;
            while ((count = input.read(buffer)) >= 0) {
                session.monitor().checkCancelled();
                digest.update(buffer, 0, count);
            }
        }
        return HexFormat.of().formatHex(digest.digest());
    }

    private void requireUnchanged(Path file, String fingerprint) throws Exception {
        if (!fingerprint.equals(digest(file)))
            throw new IllegalArgumentException("Source archive changed while reading; select the types again");
    }

    private static void removeStaging(Path root) throws IOException {
        // Only descend into the exclusively-created staging directory. Do not
        // follow links or remove the published destination on cleanup failures.
        try (var children = Files.newDirectoryStream(root)) {
            for (Path child : children) {
                if (Files.isDirectory(child, LinkOption.NOFOLLOW_LINKS)) removeStaging(child);
                else Files.delete(child);
            }
        }
        Files.delete(root);
    }
}
