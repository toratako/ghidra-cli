package ghidracli.script;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import ghidra.util.exception.CancelledException;
import ghidracli.protocol.JsonProtocol;
import ghidracli.session.ProgramSession;
import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;

import static ghidracli.protocol.JsonProtocol.errorResult;
import static ghidracli.protocol.JsonProtocol.getArgBool;
import static ghidracli.protocol.JsonProtocol.getArgString;

final class ArtifactManifest {
    private final ProgramSession session;

    ArtifactManifest(ProgramSession session) {
        this.session = session;
    }

    private static volatile String cachedGhidraVersion;

    /** Reject invalid row constraints before a script can make changes. */
    static void validateExpectations(JsonObject args) {
        if (args == null || !args.has("expect")) return;
        if (!args.get("expect").isJsonArray())
            throw new IllegalArgumentException("expect must be an array");
        JsonArray expect = args.getAsJsonArray("expect");
        for (int index = 0; index < expect.size(); index++) {
            JsonElement el = expect.get(index);
            if (!el.isJsonObject())
                throw new IllegalArgumentException("expect[" + index + "] must be an object");
            JsonObject spec = el.getAsJsonObject();
            JsonElement path = spec.get("path");
            if (path == null || !path.isJsonPrimitive() || !path.getAsJsonPrimitive().isString()
                    || path.getAsString().isEmpty())
                throw new IllegalArgumentException("expect[" + index + "].path must be a nonempty string");
            JsonElement schema = spec.get("schema");
            if (schema != null && !schema.isJsonNull()
                    && (!schema.isJsonPrimitive() || !schema.getAsJsonPrimitive().isString()))
                throw new IllegalArgumentException("expect[" + index + "].schema must be a string");
            JsonProtocol.getNonnegativeLongArg(spec, "min_rows");
        }
    }

    /**
     * Validate the caller's declared output artifacts (the "expect" array) and
     * attach a manifest for each. A missing artifact, an empty one (unless
     * allow_empty), or one below its min_rows fails the whole job.
     */
    JsonObject validateArtifacts(JsonObject result, JsonObject args, String stdout)
            throws CancelledException {
        if (args == null || !args.has("expect") || !args.get("expect").isJsonArray()) {
            return result;
        }
        JsonArray expect = args.getAsJsonArray("expect");
        if (expect.size() == 0) return result;

        boolean allowEmpty = getArgBool(args, "allow_empty", false);
        JsonArray artifacts = new JsonArray();
        List<String> failures = new ArrayList<>();

        for (JsonElement el : expect) {
            session.monitor().checkCancelled();
            JsonObject spec = el.getAsJsonObject();
            String path = getArgString(spec, "path");
            String schema = getArgString(spec, "schema");
            JsonObject manifest = buildArtifactManifest(path, schema);
            artifacts.add(manifest);

            if (!manifest.get("exists").getAsBoolean()) {
                failures.add("missing: " + manifest.get("path").getAsString());
                continue;
            }
            if (manifest.has("manifest_error")) {
                failures.add("cannot read artifact: " + manifest.get("path").getAsString()
                    + ": " + manifest.get("manifest_error").getAsString());
                continue;
            }
            if (manifest.get("bytes").getAsLong() == 0 && !allowEmpty) {
                failures.add("empty: " + manifest.get("path").getAsString());
            }
            if (spec.has("min_rows") && !spec.get("min_rows").isJsonNull()) {
                long minRows = JsonProtocol.getNonnegativeLongArg(spec, "min_rows");
                if (!manifest.has("rows")) {
                    failures.add("min_rows set but " + manifest.get("path").getAsString()
                        + " is not a row-countable (.jsonl/.ndjson) artifact");
                } else if (manifest.get("rows").getAsLong() < minRows) {
                    failures.add(manifest.get("path").getAsString() + " has "
                        + manifest.get("rows").getAsLong() + " rows, expected >= " + minRows);
                }
            }
        }

        result.add("artifacts", artifacts);
        if (failures.isEmpty()) {
            return result;
        }
        JsonObject err = errorResult("Artifact validation failed: " + String.join("; ", failures));
        err.add("artifacts", artifacts);
        err.addProperty("stdout", stdout);
        return err;
    }

    /** Manifest for one output file: existence, size, row count, checksum, provenance. */
    private JsonObject buildArtifactManifest(String rawPath, String schema)
            throws CancelledException {
        JsonObject m = new JsonObject();
        File f = new File(rawPath).getAbsoluteFile();
        m.addProperty("path", f.getAbsolutePath());
        if (schema != null) m.addProperty("schema", schema);
        if (!f.exists() || !f.isFile()) {
            m.addProperty("exists", false);
            return m;
        }
        m.addProperty("exists", true);
        m.addProperty("bytes", f.length());
        String lower = rawPath.toLowerCase();
        try {
            if (lower.endsWith(".jsonl") || lower.endsWith(".ndjson")) {
                m.addProperty("rows", countLines(f));
            }
            m.addProperty("sha256", sha256File(f));
        } catch (IOException e) {
            m.addProperty("manifest_error", e.getMessage());
        }
        if (session.program() != null) {
            m.addProperty("program", session.programName());
            String binSha = session.program().getExecutableSHA256();
            if (binSha != null && !binSha.isEmpty()) m.addProperty("binary_sha256", binSha);
            m.addProperty("executable_format", session.program().getExecutableFormat());
        }
        String gv = ghidraVersion();
        if (!gv.isEmpty()) m.addProperty("ghidra_version", gv);
        return m;
    }

    /** Stream the file counting newlines; handles multi-GB JSONL exports. */
    private long countLines(File f) throws IOException, CancelledException {
        long count = 0;
        boolean previousCr = false;
        boolean unterminated = false;
        byte[] buf = new byte[65536];
        try (InputStream in = new BufferedInputStream(new FileInputStream(f))) {
            int n;
            while ((n = in.read(buf)) != -1) {
                session.monitor().checkCancelled();
                for (int i = 0; i < n; i++) {
                    byte b = buf[i];
                    if (b == '\r') {
                        count++;
                        previousCr = true;
                        unterminated = false;
                    } else if (b == '\n') {
                        if (!previousCr) count++;
                        previousCr = false;
                        unterminated = false;
                    } else {
                        previousCr = false;
                        unterminated = true;
                    }
                }
            }
        }
        session.monitor().checkCancelled();
        return count + (unterminated ? 1 : 0);
    }

    /** Streaming SHA-256 so large artifacts are not fully buffered. */
    private String sha256File(File f) throws IOException, CancelledException {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] buf = new byte[65536];
            try (InputStream in = new BufferedInputStream(new FileInputStream(f))) {
                int n;
                while ((n = in.read(buf)) != -1) {
                    session.monitor().checkCancelled();
                    md.update(buf, 0, n);
                }
            }
            session.monitor().checkCancelled();
            byte[] digest = md.digest();
            StringBuilder sb = new StringBuilder(digest.length * 2);
            for (byte b : digest) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IOException("SHA-256 unavailable", e);
        }
    }

    private String ghidraVersion() {
        if (cachedGhidraVersion != null) return cachedGhidraVersion;
        try {
            Object v = Class.forName("ghidra.framework.Application")
                .getMethod("getApplicationVersion").invoke(null);
            cachedGhidraVersion = v == null ? "" : v.toString();
        } catch (Throwable t) {
            cachedGhidraVersion = "";
        }
        return cachedGhidraVersion;
    }
}
