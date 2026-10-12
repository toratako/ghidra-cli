import com.google.gson.JsonObject;
import ghidra.app.script.GhidraScript;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.CancellationException;

/** Cancel shared lookup and definition traversal against a saved, read-only database. */
public class CheckTypeQueriesReadOnly extends GhidraScript {
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
        TaskMonitor[] requestMonitor = {new TaskMonitorAdapter(true)};
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
            Class<?> resolverClass = loader.loadClass(prefix + "types.TypeResolver");
            Object resolver = resolverClass.getConstructor(sessionClass).newInstance(session);
            Class<?> commandsClass = loader.loadClass(prefix + "types.TypeCommands");
            Object commands = commandsClass.getConstructor(sessionClass, resolverClass)
                .newInstance(session, resolver);
            var get = commandsClass.getMethod("handleTypeGet", JsonObject.class);
            Class<?> graphClass = loader.loadClass(prefix + "types.TypeArchiveGraph");
            var graph = graphClass.getDeclaredConstructor(Collection.class, TaskMonitor.class);
            graph.setAccessible(true);
            long before = program.getModificationNumber();

            for (String method : new String[] {"resolveDataType", "resolveRegisteredDataType"}) {
                var lookup = resolverClass.getMethod(method, String.class);
                Object complete = lookup.invoke(resolver, "LookupTarget");
                if (complete == null) throw new IllegalStateException("Missing lookup fixture");
                requestMonitor[0] = new TaskMonitorAdapter(true) {
                    private int checks;
                    @Override
                    public boolean isCancelled() {
                        if (++checks == 3) cancel();
                        return super.isCancelled();
                    }
                };
                expectCancelled(() -> lookup.invoke(resolver, "LookupTarget"), CancellationException.class);
                requestMonitor[0] = new TaskMonitorAdapter(true);
                if (!complete.equals(lookup.invoke(resolver, "LookupTarget")))
                    throw new IllegalStateException("Fresh type lookup did not recover");
            }

            for (String path : new String[] {"/QueryEnum", "/functions/QueryFunction"}) {
                JsonObject args = new JsonObject();
                args.addProperty("name", path);
                JsonObject complete = (JsonObject) get.invoke(commands, args);
                requestMonitor[0] = cancellingRows();
                expectCancelled(() -> get.invoke(commands, args), CancelledException.class);
                requestMonitor[0] = new TaskMonitorAdapter(true);
                if (!complete.equals(get.invoke(commands, args)))
                    throw new IllegalStateException("Fresh definition query did not recover: " + path);

                var roots = List.of(program.getDataTypeManager().getDataType(path));
                graph.newInstance(roots, requestMonitor[0]);
                requestMonitor[0] = cancellingRows();
                expectCancelled(() -> graph.newInstance(roots, requestMonitor[0]), CancelledException.class);
                requestMonitor[0] = new TaskMonitorAdapter(true);
                graph.newInstance(roots, requestMonitor[0]);
            }
            if (program.getModificationNumber() != before)
                throw new IllegalStateException("Type queries changed the Program");
        } finally {
            try {
                if (session != null) {
                    var close = sessionClass.getDeclaredMethod("closeProgram");
                    close.setAccessible(true);
                    close.invoke(session);
                }
            } finally { program.release(reader); }
        }
    }

    private static TaskMonitor cancellingRows() {
        return new TaskMonitorAdapter(true) {
            private int checks;
            @Override
            public void checkCancelled() throws CancelledException {
                if (++checks == 3) cancel();
                super.checkCancelled();
            }
        };
    }

    private interface Action { void run() throws Exception; }

    private static void expectCancelled(Action action, Class<? extends Throwable> expected) throws Exception {
        try {
            action.run();
            throw new IllegalStateException("Cancelled type traversal returned successfully");
        } catch (InvocationTargetException failure) {
            if (!expected.isInstance(failure.getCause())) throw failure;
        }
    }
}
