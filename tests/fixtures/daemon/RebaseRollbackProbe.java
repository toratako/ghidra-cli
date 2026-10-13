import com.google.gson.JsonObject;
import ghidra.app.script.GhidraScript;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;

public class RebaseRollbackProbe extends GhidraScript {
  private String fault;
  private Program selected;
  private final TaskMonitorAdapter requestMonitor = new TaskMonitorAdapter(true);

  private void require(boolean condition, String message) {
    if (!condition) throw new IllegalStateException(message);
  }

  public void run() throws Exception {
    var folder =
        state.getProject().getProjectData().getRootFolder().createFolder(getScriptArgs()[0]);
    DomainFile file = currentProgram.getDomainFile().copyTo(folder, monitor);
    Object owner = new Object();
    Program real = (Program) file.getDomainObject(owner, true, false, monitor);
    Object session = null;
    try {
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
      var loader = caller.getClassLoader();
      String prefix =
          caller.getPackageName().substring(0, caller.getPackageName().lastIndexOf('.') + 1);

      selected =
          (Program)
              Proxy.newProxyInstance(
                  Program.class.getClassLoader(),
                  new Class<?>[] {Program.class},
                  (proxy, method, args) -> {
                    Object result;
                    try {
                      result = method.invoke(real, args);
                    } catch (InvocationTargetException error) {
                      throw error.getCause();
                    }
                    if (method.getName().equals("setImageBase") && fault != null) {
                      require(
                          real.getImageBase().getOffset() == 0x5000,
                          "Failure preceded native mutation");
                      if (fault.equals("cancel")) requestMonitor.cancel();
                      else throw new IllegalStateException("injected error after native rebase");
                    }
                    return result;
                  });
      var accessClass = loader.loadClass(prefix + "session.ScriptAccess");
      Object access =
          Proxy.newProxyInstance(
              loader,
              new Class<?>[] {accessClass},
              (proxy, method, args) -> {
                switch (method.getName()) {
                  case "program":
                    return selected;
                  case "setProgram":
                    selected = (Program) args[0];
                    return null;
                  case "state":
                    return state;
                  case "monitor":
                    return requestMonitor;
                  case "logError":
                    printerr((String) args[0]);
                    return null;
                  default:
                    throw new UnsupportedOperationException(method.getName());
                }
              });
      var sessionClass = loader.loadClass(prefix + "session.ProgramSession");
      var sessionConstructor = sessionClass.getDeclaredConstructor(accessClass);
      sessionConstructor.setAccessible(true);
      session = sessionConstructor.newInstance(access);
      var dispatcherClass = loader.loadClass(prefix + "runtime.CommandDispatcher");
      var dispatcherConstructor = dispatcherClass.getDeclaredConstructor(sessionClass);
      dispatcherConstructor.setAccessible(true);
      Object dispatcher = dispatcherConstructor.newInstance(session);
      var execute = dispatcherClass.getDeclaredMethod("execute", String.class, JsonObject.class);
      execute.setAccessible(true);
      var args = new JsonObject();
      args.addProperty("base", "0x5000");
      for (String mode : new String[] {"error", "cancel"}) {
        fault = mode;
        var response = (JsonObject) execute.invoke(dispatcher, "program_rebase", args);
        require(response.get("status").getAsString().equals("error"), response.toString());
        var detail = response.getAsJsonObject("detail");
        require(detail.get("rolled_back").getAsBoolean(), response.toString());
        require(!detail.has("partial_changes_saved"), response.toString());
        if (mode.equals("cancel"))
          require(detail.get("cancelled").getAsBoolean(), response.toString());
        requestMonitor.clearCancelled();
        require(real.getImageBase().getOffset() == 0x1000, "Failed rebase retained image base");
        require(
            real.getMemory().getBlock("code").getStart().getOffset() == 0x2000,
            "Failed rebase retained block movement");
        var code = real.getAddressFactory().getDefaultAddressSpace().getAddress(0x2000);
        require(
            real.getFunctionManager().getFunctionAt(code).getName().equals("rebase_function"),
            "Rollback lost metadata");
        Object reader = new Object();
        Program saved =
            (Program)
                file.getReadOnlyDomainObject(reader, DomainFile.DEFAULT_VERSION, TaskMonitor.DUMMY);
        try {
          require(
              saved.getImageBase().getOffset() == 0x1000, "Failed rebase reached saved database");
        } finally {
          saved.release(reader);
        }
      }
      fault = null;
      var response = (JsonObject) execute.invoke(dispatcher, "program_rebase", args);
      require(response.get("status").getAsString().equals("success"), response.toString());
    } finally {
      fault = null;
      requestMonitor.clearCancelled();
      try {
        if (session != null) {
          var close = session.getClass().getDeclaredMethod("closeProgram");
          close.setAccessible(true);
          close.invoke(session);
        }
      } finally {
        real.release(owner);
      }
    }
  }
}
