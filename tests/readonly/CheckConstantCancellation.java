import com.google.gson.JsonObject;
import ghidra.app.script.GhidraScript;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;

/** Cancel deterministically after some instruction operands have been visited. */
public class CheckConstantCancellation extends GhidraScript {
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
        TaskMonitor[] requestMonitor = {new TaskMonitorAdapter(true) {
            private int checks;
            @Override
            public void checkCancelled() throws CancelledException {
                if (++checks == 12) cancel();
                super.checkCancelled();
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
            var constructor = sessionClass.getDeclaredConstructor(accessClass);
            constructor.setAccessible(true);
            session = constructor.newInstance(access);
            Class<?> resolverClass = loader.loadClass(prefix + "query.AddressResolver");
            var resolverConstructor = resolverClass.getDeclaredConstructor(sessionClass);
            resolverConstructor.setAccessible(true);
            Object resolver = resolverConstructor.newInstance(session);
            var find = loader.loadClass(prefix + "listing.ConstantSearch")
                .getDeclaredMethod("find", sessionClass, resolverClass, JsonObject.class);
            find.setAccessible(true);
            JsonObject args = new JsonObject();
            args.addProperty("value", "-1");
            try {
                find.invoke(null, session, resolver, args);
                throw new IllegalStateException("Cancelled scan returned a successful partial result");
            } catch (InvocationTargetException failure) {
                if (!(failure.getCause() instanceof CancelledException)) throw failure;
            }
            requestMonitor[0] = new TaskMonitorAdapter(true);
            JsonObject result = (JsonObject) find.invoke(null, session, resolver, args);
            if (result.get("count").getAsInt() != 6) {
                throw new IllegalStateException("Fresh monitor did not recover the full query: " + result);
            }
        } finally {
            try {
                if (session != null) {
                    var close = sessionClass.getDeclaredMethod("closeProgram");
                    close.setAccessible(true);
                    close.invoke(session);
                }
            } finally {
                program.release(reader);
            }
        }
    }
}
