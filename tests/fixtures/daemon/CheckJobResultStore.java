
import ghidra.app.script.GhidraScript;
import com.google.gson.JsonObject;
import java.lang.reflect.*;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class CheckJobResultStore extends GhidraScript {
    static void check(boolean condition, String message) {
        if (!condition) throw new IllegalStateException(message);
    }
    static Method method(Class<?> type, String name, Class<?>... args) throws Exception {
        Method method = type.getDeclaredMethod(name, args);
        method.setAccessible(true);
        return method;
    }
    static Field field(Class<?> type, String name) throws Exception {
        Field field = type.getDeclaredField(name);
        field.setAccessible(true);
        return field;
    }
    public void run() throws Exception {
        ClassLoader loader = StackWalker.getInstance(StackWalker.Option.RETAIN_CLASS_REFERENCE)
            .walk(frames -> frames.map(StackWalker.StackFrame::getDeclaringClass)
                .filter(type -> type.getName().equals("ghidracli.script.ScriptCommands"))
                .findFirst().orElseThrow()).getClassLoader();
        Class<?> type = loader.loadClass("ghidracli.runtime.JobResultStore");
        Class<?> entry = loader.loadClass("ghidracli.runtime.JobResultStore$Entry");
        Constructor<?> constructor = type.getDeclaredConstructor(long.class, int.class, int.class);
        constructor.setAccessible(true);
        Object store = constructor.newInstance(10L, 50, 32);
        Method snapshot = method(type, "snapshot", JsonObject.class);
        Method retain = method(type, "retain", byte[].class, long.class);
        Method expire = method(type, "expire", long.class);
        Method forget = method(type, "forget", entry);
        Field body = field(entry, "body"), state = field(entry, "state");
        JsonObject response = new JsonObject();
        response.addProperty("value", "éééé");
        byte[] encoded = (byte[]) snapshot.invoke(store, response);
        check(Arrays.equals(encoded, response.toString().getBytes(StandardCharsets.UTF_8)), "UTF-8 snapshot");
        Object first = retain.invoke(store, encoded, 100L);
        byte[] held = (byte[]) body.get(first);
        response.addProperty("value", "changed");
        check(new String(held, StandardCharsets.UTF_8).contains("éééé"), "snapshot changed");
        Object second = retain.invoke(store, encoded, 101L);
        Object third = retain.invoke(store, encoded, 102L);
        check("evicted".equals(state.get(first)) && body.get(first) == null, "byte eviction");
        check(Arrays.equals(held, encoded), "in-flight reader lost its snapshot");
        expire.invoke(store, 110L);
        check("available".equals(state.get(second)), "expired early");
        expire.invoke(store, 111L);
        check("expired".equals(state.get(second)) && body.get(second) == null, "expiry boundary");
        forget.invoke(store, third);
        check(field(type, "retainedBytes").getLong(store) == 0, "history eviction leaked bytes");
        response.addProperty("value", "é".repeat(40));
        byte[] oversized = (byte[]) snapshot.invoke(store, response);
        check(oversized == null, "per-result UTF-8 limit");
        Object missing = retain.invoke(store, oversized, 120L);
        check("too_large".equals(state.get(missing)), "oversized reason");
        check(field(type, "retainedBytes").getLong(store) == 0, "oversized result retained");
        // Split a surrogate pair at writer/encoder buffer boundaries and enforce
        // byte limits when the final buffered output is flushed.
        for (int prefix : new int[] {1013, 8181}) {
            JsonObject boundary = new JsonObject();
            boundary.addProperty("value", "a".repeat(prefix) + "\uD83D\uDE00é");
            byte[] expected = boundary.toString().getBytes(StandardCharsets.UTF_8);
            Object exact = constructor.newInstance(10L, expected.length, expected.length);
            check(Arrays.equals((byte[]) snapshot.invoke(exact, boundary), expected), "exact UTF-8 limit");
            Object tooSmall = constructor.newInstance(10L, expected.length, expected.length - 1);
            check(snapshot.invoke(tooSmall, boundary) == null, "buffered UTF-8 overflow");
        }
        // History eviction must remove the lookup and release its retained body too.
        Class<?> schedulerType = loader.loadClass("ghidracli.runtime.JobScheduler");
        Class<?> recordType = loader.loadClass("ghidracli.runtime.JobRecord");
        Constructor<?> schedulerConstructor = schedulerType.getDeclaredConstructors()[0];
        schedulerConstructor.setAccessible(true);
        Object scheduler = schedulerConstructor.newInstance(null, null);
        Constructor<?> recordConstructor = recordType.getDeclaredConstructor(String.class, String.class);
        recordConstructor.setAccessible(true);
        Method complete = method(schedulerType, "retainCompletedJob", recordType, byte[].class);
        java.util.Map jobs = (java.util.Map) field(schedulerType, "jobs").get(scheduler);
        int maxJobs = field(type, "MAX_JOBS").getInt(null);
        Object oldest = null;
        for (int i = 0; i <= maxJobs; i++) {
            Object record = recordConstructor.newInstance(new java.util.UUID(0, i).toString(), "stats");
            field(recordType, "finishedAt").setLong(record, System.currentTimeMillis());
            jobs.put(field(recordType, "id").get(record), record);
            complete.invoke(scheduler, record, encoded);
            if (i == 0) oldest = record;
        }
        check(jobs.size() == maxJobs, "history count limit");
        check(!jobs.containsKey(new java.util.UUID(0, 0).toString()), "old history remains addressable");
        check(body.get(field(recordType, "result").get(oldest)) == null, "history retains evicted bytes");
        println("job result limits checked");
    }
}

