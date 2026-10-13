import com.google.gson.JsonObject;
import ghidra.app.script.GhidraScript;
import ghidra.framework.model.DomainFile;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.QWordDataType;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;

public class DefineDataFailureProbe extends GhidraScript {
  private Program real;
  private Program selected;
  private Address start;
  private String fault;
  private boolean nativeClear;
  private boolean observed;
  private int createCalls;
  private final TaskMonitorAdapter requestMonitor =
      new TaskMonitorAdapter(true) {
        @Override
        public synchronized boolean isCancelled() {
          if (nativeClear && fault.equals("cancel")) {
            check(
                real.getReferenceManager().getReferencesFrom(start).length == 0,
                "Cancellation preceded native reference removal");
            observed = true;
            cancel();
          }
          return super.isCancelled();
        }
      };

  private static void check(boolean condition, String message) {
    if (!condition) throw new IllegalStateException(message);
  }

  private void checkPreserved(Program program) {
    Address address = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000);
    var data = program.getListing().getDefinedDataAt(address);
    check(
        data != null && data.getLength() == 8 && data.getDataType().getName().equals("qword"),
        "Failed definition did not restore the original data");
    check(
        program.getReferenceManager().getReference(address, address.add(16), 0) != null,
        "Failed definition did not restore the original reference");
    check(
        program.getEquateTable().getEquate("kept_equate") != null,
        "Failed definition did not restore the original equate");
  }

  public void run() throws Exception {
    String name = getScriptArgs()[0];
    fault = getScriptArgs()[1];
    var language =
        DefaultLanguageService.getLanguageService()
            .getLanguage(new LanguageID("x86:LE:64:default"));
    real = new ProgramDB(name, language, language.getDefaultCompilerSpec(), this);
    Object session = null;
    DomainFile file = null;
    try {
      start = real.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000);
      int tx = real.startTransaction("definition rollback fixture");
      try {
        real.getMemory().createInitializedBlock("storage", start, 32, (byte) 0, monitor, false);
        real.getListing().createData(start, QWordDataType.dataType);
        real.getReferenceManager()
            .addMemoryReference(start, start.add(16), RefType.DATA, SourceType.USER_DEFINED, 0);
        real.getEquateTable().createEquate("kept_equate", 0).addReference(start, 0);
      } finally {
        real.endTransaction(tx, true);
      }
      file = state.getProject().getProjectData().getRootFolder().createFile(name, real, monitor);

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
      Listing listing =
          (Listing)
              Proxy.newProxyInstance(
                  Listing.class.getClassLoader(),
                  new Class<?>[] {Listing.class},
                  (proxy, method, args) -> {
                    if (method.getName().equals("createData")) {
                      createCalls++;
                      if (fault.equals("null")) {
                        check(
                            real.getListing().getDefinedDataAt(start) == null
                                && real.getReferenceManager().getReferencesFrom(start).length == 0,
                            "Failure preceded native forced clearing");
                        observed = true;
                        // CodeManager.createCodeUnit can return null after a database error.
                        return null;
                      }
                    }
                    nativeClear = method.getName().equals("clearCodeUnits");
                    try {
                      return method.invoke(real.getListing(), args);
                    } catch (InvocationTargetException error) {
                      throw error.getCause();
                    } finally {
                      nativeClear = false;
                    }
                  });
      selected =
          (Program)
              Proxy.newProxyInstance(
                  Program.class.getClassLoader(),
                  new Class<?>[] {Program.class},
                  (proxy, method, args) -> {
                    if (method.getName().equals("getListing")) return listing;
                    try {
                      return method.invoke(real, args);
                    } catch (InvocationTargetException error) {
                      throw error.getCause();
                    }
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
      session = sessionClass.getConstructor(accessClass).newInstance(access);
      var dispatcherClass = loader.loadClass(prefix + "runtime.CommandDispatcher");
      var constructor = dispatcherClass.getDeclaredConstructor(sessionClass);
      constructor.setAccessible(true);
      Object dispatcher = constructor.newInstance(session);
      var args = new JsonObject();
      args.addProperty("address", "0x1000");
      args.addProperty("type_name", "uint32_t");
      args.addProperty("force", true);
      var execute = dispatcherClass.getDeclaredMethod("execute", String.class, JsonObject.class);
      execute.setAccessible(true);
      var response = (JsonObject) execute.invoke(dispatcher, "define_data", args);
      check(observed, "Test did not reach native " + fault + " failure: " + response);
      check(response.get("status").getAsString().equals("error"), response.toString());
      var detail = response.getAsJsonObject("detail");
      check(detail.get("rolled_back").getAsBoolean(), response.toString());
      if (fault.equals("cancel")) {
        check(detail.get("cancelled").getAsBoolean(), response.toString());
        check(createCalls == 0, "Data creation continued after cancellation");
      } else {
        check(
            response.get("message").getAsString().contains("Ghidra did not create data"),
            response.toString());
        check(createCalls == 1, "Test did not reach failed data creation");
      }
      requestMonitor.clearCancelled();
      checkPreserved(real);
      Object reader = new Object();
      Program saved =
          (Program)
              file.getReadOnlyDomainObject(reader, DomainFile.DEFAULT_VERSION, TaskMonitor.DUMMY);
      try {
        checkPreserved(saved);
      } finally {
        saved.release(reader);
      }
    } finally {
      requestMonitor.clearCancelled();
      try {
        if (session != null) session.getClass().getMethod("closeProgram").invoke(session);
      } finally {
        real.release(this);
        if (file != null) file.delete();
      }
    }
  }
}
