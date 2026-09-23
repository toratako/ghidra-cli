package ghidracli.runtime;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;

/** Bounded immutable JSON snapshots. Membership is guarded by the scheduler lock. */
final class JobResultStore {
    static final int MAX_JOBS = 1000;
    private static final long RETENTION_MS = 30 * 60 * 1000;
    private static final int MAX_BYTES = 64 * 1024 * 1024;
    private static final int MAX_RESULT_BYTES = 16 * 1024 * 1024;
    private static final Gson GSON = new GsonBuilder().serializeNulls().create();
    private final long retentionMs;
    private final int maxBytes;
    private final int maxResultBytes;
    private final ArrayDeque<Entry> retained = new ArrayDeque<>();
    private long retainedBytes;

    static final class Entry {
        final long expiresAt;
        byte[] body;
        String state;

        Entry(byte[] body, long expiresAt) {
            this.body = body;
            this.expiresAt = expiresAt;
            state = body == null ? "too_large" : "available";
        }

        JsonObject status() {
            JsonObject result = new JsonObject();
            result.addProperty("state", state);
            result.addProperty("expires_at_ms", expiresAt);
            return result;
        }
    }

    JobResultStore() { this(RETENTION_MS, MAX_BYTES, MAX_RESULT_BYTES); }

    JobResultStore(long retentionMs, int maxBytes, int maxResultBytes) {
        this.retentionMs = retentionMs;
        this.maxBytes = maxBytes;
        this.maxResultBytes = maxResultBytes;
    }

    /** Encode outside the scheduler lock; stop allocating when the per-result limit is hit. */
    byte[] snapshot(JsonObject response) {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        OutputStream bounded = new OutputStream() {
            @Override public void write(int value) {
                if (bytes.size() >= maxResultBytes) throw new ResultTooLarge();
                bytes.write(value);
            }
            @Override public void write(byte[] buffer, int offset, int length) {
                if ((long) bytes.size() + length > maxResultBytes) throw new ResultTooLarge();
                bytes.write(buffer, offset, length);
            }
        };
        try {
            OutputStreamWriter writer = new OutputStreamWriter(bounded, StandardCharsets.UTF_8);
            GSON.toJson(response, writer);
            writer.flush();
            return bytes.toByteArray();
        } catch (ResultTooLarge error) {
            return null;
        } catch (IOException error) {
            throw new IllegalStateException("Cannot encode job result", error);
        }
    }

    Entry retain(byte[] body, long now) {
        expire(now);
        Entry entry = new Entry(body, now + retentionMs);
        if (body != null) {
            while (!retained.isEmpty() && retainedBytes + body.length > maxBytes) {
                removeFirst("evicted");
            }
            if (body.length > maxBytes) {
                entry.body = null;
                entry.state = "too_large";
            } else {
                retained.addLast(entry);
                retainedBytes += body.length;
            }
        }
        return entry;
    }

    void expire(long now) {
        while (!retained.isEmpty() && retained.peekFirst().expiresAt <= now) {
            removeFirst("expired");
        }
    }

    void forget(Entry entry) {
        if (entry != null && entry.body != null && retained.remove(entry)) {
            retainedBytes -= entry.body.length;
            entry.body = null;
        }
    }

    private void removeFirst(String reason) {
        Entry entry = retained.removeFirst();
        retainedBytes -= entry.body.length;
        entry.body = null;
        entry.state = reason;
    }

    private static final class ResultTooLarge extends RuntimeException {}
}
