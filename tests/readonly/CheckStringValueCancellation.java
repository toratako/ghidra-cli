import com.google.gson.JsonObject;
import ghidra.app.script.GhidraScript;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;

/** Cancel inside native terminator scanning, after traversal has selected a char array. */
public class CheckStringValueCancellation extends GhidraScript {
    public void run() throws Exception {
        Class<?> caller = StackWalker.getInstance(StackWalker.Option.RETAIN_CLASS_REFERENCE)
            .walk(frames -> frames.map(StackWalker.StackFrame::getDeclaringClass)
                .filter(type -> type.getSimpleName().equals("ScriptCommands")
                    && type.getPackageName().equals("ghidracli.script"))
                .findFirst().orElseThrow());
        ClassLoader loader = caller.getClassLoader();
        String prefix = caller.getPackageName()
            .substring(0, caller.getPackageName().lastIndexOf('.') + 1);
        Object reader = new Object();
        Program program = (Program) currentProgram.getDomainFile()
            .getReadOnlyDomainObject(reader, DomainFile.DEFAULT_VERSION, TaskMonitor.DUMMY);
        Program[] selected = {program};
        int[] nativeReads = {0};
        TaskMonitor[] requestMonitor = {new TaskMonitorAdapter(true) {
            @Override
            public boolean isCancelled() {
                boolean nativeScan = StackWalker.getInstance().walk(frames -> frames.anyMatch(frame ->
                    frame.getClassName().equals("ghidra.program.model.data.StringDataInstance")
                        && frame.getMethodName().equals("getNullTerminatedLength")));
                if (nativeScan && ++nativeReads[0] == 128) cancel();
                return super.isCancelled();
            }
        }};
        Class<?> sessionClass = loader.loadClass(prefix + "session.ProgramSession");
        Object session = null;
        try {
            Class<?> accessClass = loader.loadClass(prefix + "session.ScriptAccess");
            Object access = Proxy.newProxyInstance(loader, new Class<?>[] {accessClass},
                (proxy, method, args) -> {
                    switch (method.getName()) {
                        case "program": return selected[0];
                        case "setProgram": selected[0] = (Program) args[0]; return null;
                        case "monitor": return requestMonitor[0];
                        default: throw new UnsupportedOperationException(method.getName());
                    }
                });
            session = sessionClass.getConstructor(accessClass).newInstance(access);
            Class<?> queryClass = loader.loadClass(prefix + "listing.StringQueries");
            Object query = queryClass.getConstructor(sessionClass).newInstance(session);
            var list = queryClass.getDeclaredMethod("list", JsonObject.class, String.class);
            list.setAccessible(true);
            try {
                list.invoke(query, new JsonObject(), null);
                throw new IllegalStateException("Cancelled native string scan returned successful rows");
            } catch (InvocationTargetException failure) {
                if (!(failure.getCause() instanceof CancelledException)) throw failure;
            }
            if (nativeReads[0] != 128) {
                throw new IllegalStateException("Cancellation did not occur inside native string scanning");
            }
            requestMonitor[0] = new TaskMonitorAdapter(true);
            var rows = (com.google.gson.JsonArray) list.invoke(query, new JsonObject(), null);
            if (rows.size() != 3 || rows.get(2).getAsJsonObject().get("char_length").getAsInt() != 65536) {
                throw new IllegalStateException("Fresh monitor did not recover complete string values");
            }
        } finally {
            try {
                if (session != null) sessionClass.getMethod("closeProgram").invoke(session);
            } finally {
                program.release(reader);
            }
        }
    }
}
