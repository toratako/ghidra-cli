import ghidra.app.script.GhidraScript;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.Set;
import java.util.concurrent.CancellationException;

/** Lookup must leave the shared program lane promptly when its job is cancelled. */
public class CheckAddressLookupCancellation extends GhidraScript {
  private static final class LookupMonitor extends TaskMonitorAdapter {
    private int checks;

    LookupMonitor() {
      super(true);
    }

    @Override
    public boolean isCancelled() {
      if (++checks == 5) cancel();
      return super.isCancelled();
    }
  }

  private void cancelled(Method method, Object resolver, String target) throws Exception {
    try {
      method.invoke(resolver, target);
      throw new IllegalStateException("Cancelled lookup returned a result: " + target);
    } catch (InvocationTargetException failure) {
      if (!(failure.getCause() instanceof CancellationException)) throw failure;
    }
  }

  public void run() throws Exception {
    Class<?> caller =
        StackWalker.getInstance(StackWalker.Option.RETAIN_CLASS_REFERENCE)
            .walk(
                frames ->
                    frames
                        .map(StackWalker.StackFrame::getDeclaringClass)
                        .filter(
                            type ->
                                type.getSimpleName().equals("ScriptCommands")
                                    && type.getPackageName().equals("ghidracli.script"))
                        .findFirst()
                        .orElseThrow());
    ClassLoader loader = caller.getClassLoader();
    String prefix =
        caller.getPackageName().substring(0, caller.getPackageName().lastIndexOf('.') + 1);
    Object reader = new Object();
    Program program =
        (Program)
            currentProgram
                .getDomainFile()
                .getReadOnlyDomainObject(reader, DomainFile.DEFAULT_VERSION, TaskMonitor.DUMMY);
    Program[] selected = {program};
    TaskMonitor[] requestMonitor = {new LookupMonitor()};
    Class<?> sessionClass = loader.loadClass(prefix + "session.ProgramSession");
    Object session = null;
    try {
      Class<?> accessClass = loader.loadClass(prefix + "session.ScriptAccess");
      Object access =
          Proxy.newProxyInstance(
              loader,
              new Class<?>[] {accessClass},
              (proxy, method, args) -> {
                switch (method.getName()) {
                  case "program":
                    return selected[0];
                  case "setProgram":
                    selected[0] = (Program) args[0];
                    return null;
                  case "monitor":
                    return requestMonitor[0];
                  default:
                    throw new UnsupportedOperationException(method.getName());
                }
              });
      session = sessionClass.getConstructor(accessClass).newInstance(access);
      Class<?> resolverClass = loader.loadClass(prefix + "query.AddressResolver");
      Object resolver = resolverClass.getConstructor(sessionClass).newInstance(session);
      Method resolve = resolverClass.getMethod("resolveAddress", String.class);
      cancelled(resolve, resolver, "add");
      requestMonitor[0] = new TaskMonitorAdapter(true);
      Address address = (Address) resolve.invoke(resolver, "add");
      if (address.getOffset() != 0x1000) {
        throw new IllegalStateException("Fresh monitor did not recover named lookup");
      }

      Address external = program.getFunctionManager().getExternalFunctions().next().getEntryPoint();
      String target =
          (String)
              loader
                  .loadClass(prefix + "query.AddressCodec")
                  .getMethod("format", Address.class)
                  .invoke(null, external);
      Method xrefs = resolverClass.getMethod("resolveXrefTargets", String.class);
      requestMonitor[0] = new LookupMonitor();
      cancelled(xrefs, resolver, target);
      requestMonitor[0] = new TaskMonitorAdapter(true);
      Set<?> targets = (Set<?>) xrefs.invoke(resolver, target);
      if (targets.size() != 2
          || !targets.contains(external)
          || !targets.contains(
              program.getAddressFactory().getDefaultAddressSpace().getAddress(0x1606))) {
        throw new IllegalStateException(
            "Fresh monitor did not recover external/thunk lookup: " + targets);
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
