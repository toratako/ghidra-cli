import com.google.gson.JsonObject;
import ghidra.app.script.GhidraScript;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;

/** Cancel on a real function-symbol scan before a resize can mutate the saved database. */
public class CheckSavedVariablePropagationCancellation extends GhidraScript {
  private static Object invoke(Method method, Object owner, Object[] args) throws Throwable {
    try {
      return method.invoke(owner, args);
    } catch (InvocationTargetException failure) {
      throw failure.getCause();
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
    Program saved =
        (Program)
            currentProgram
                .getDomainFile()
                .getReadOnlyDomainObject(reader, DomainFile.DEFAULT_VERSION, TaskMonitor.DUMMY);
    TaskMonitor[] requestMonitor = {new TaskMonitorAdapter(true)};
    boolean[] scanned = {false};
    SymbolTable symbols =
        (SymbolTable)
            Proxy.newProxyInstance(
                SymbolTable.class.getClassLoader(),
                new Class<?>[] {SymbolTable.class},
                (proxy, method, args) -> {
                  Object result = invoke(method, saved.getSymbolTable(), args);
                  if (method.getName().equals("getSymbols")
                      && args != null
                      && args.length == 3
                      && args[1] == SymbolType.FUNCTION) {
                    return Proxy.newProxyInstance(
                        method.getReturnType().getClassLoader(),
                        new Class<?>[] {method.getReturnType()},
                        (iterator, operation, inputs) -> {
                          Object entry = invoke(operation, result, inputs);
                          if (operation.getName().equals("next")) {
                            scanned[0] = true;
                            requestMonitor[0].cancel();
                          }
                          return entry;
                        });
                  }
                  return result;
                });
    Program program =
        (Program)
            Proxy.newProxyInstance(
                Program.class.getClassLoader(),
                new Class<?>[] {Program.class},
                (proxy, method, args) ->
                    method.getName().equals("getSymbolTable")
                        ? symbols
                        : invoke(method, saved, args));
    Program[] selected = {program};
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
      Class<?> resolverClass = loader.loadClass(prefix + "types.TypeResolver");
      Object resolver = resolverClass.getConstructor(sessionClass).newInstance(session);
      Class<?> commandsClass = loader.loadClass(prefix + "types.TypeResizeCommands");
      Object commands =
          commandsClass.getConstructor(sessionClass, resolverClass).newInstance(session, resolver);
      JsonObject args = new JsonObject();
      args.addProperty("type_name", "/Audit/ResizeReturn");
      args.addProperty("size", 8);
      long before = saved.getModificationNumber();
      try {
        commandsClass.getMethod("handleResize", JsonObject.class).invoke(commands, args);
        throw new IllegalStateException("Cancelled propagation scan returned success");
      } catch (InvocationTargetException failure) {
        if (!(failure.getCause() instanceof CancelledException)) throw failure;
      }
      if (!scanned[0]
          || saved.getModificationNumber() != before
          || saved.getDataTypeManager().getDataType("/Audit/ResizeReturn").getLength() != 4) {
        throw new IllegalStateException("Cancellation did not preserve the saved definition");
      }
    } finally {
      requestMonitor[0] = new TaskMonitorAdapter(true);
      try {
        if (session != null) sessionClass.getMethod("closeProgram").invoke(session);
      } finally {
        saved.release(reader);
      }
    }
  }
}
