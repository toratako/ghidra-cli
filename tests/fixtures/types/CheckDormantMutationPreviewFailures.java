import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import ghidra.app.script.GhidraScript;
import ghidra.framework.model.DomainFile;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.LocalVariableImpl;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ReturnParameterImpl;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.IdentityHashMap;
import java.util.concurrent.Callable;

/** Real native mutations under the production preview, request and save boundaries. */
public class CheckDormantMutationPreviewFailures extends GhidraScript {
  private static final String TYPE = "/Audit/DormantCell";
  private Program real;
  private Program selected;
  private Object session;
  private Object preview;
  private Object dispatcher;
  private Method executePreview;
  private Method executeCommand;
  private TaskMonitorAdapter requestMonitor;
  private int savesToFail;
  private int saveCalls;
  private int mutationCalls;
  private int clears;
  private int cancelAtClear;
  private boolean cancelVerifyScan;
  private int verificationLookups;

  private static void check(boolean condition, String message) {
    if (!condition) throw new IllegalStateException(message);
  }

  private static Object invoke(Method method, Object owner, Object... args) throws Throwable {
    try {
      return method.invoke(owner, args);
    } catch (InvocationTargetException failure) {
      throw failure.getCause();
    }
  }

  private Address at(Program program, long offset) {
    return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
  }

  private Function createFunction(String name, long offset) throws Exception {
    Address entry = at(real, offset);
    return real.getFunctionManager()
        .createFunction(name, entry, new AddressSet(entry), SourceType.USER_DEFINED);
  }

  private void createProgram(String folder, String name) throws Exception {
    var language =
        DefaultLanguageService.getLanguageService()
            .getLanguage(new LanguageID("x86:LE:32:default"));
    real = new ProgramDB(name, language, language.getDefaultCompilerSpec(), this);
    int transaction = real.startTransaction("dormant preview fixture");
    try {
      real.getMemory()
          .createInitializedBlock("fixture", at(real, 0x1000), 0x100, (byte) 0, monitor, false);
      var type =
          real.getDataTypeManager()
              .addDataType(
                  new StructureDataType(new CategoryPath("/Audit"), "DormantCell", 4), null);
      type.setDescription("baseline");
      var owner = createFunction("owner", 0x1000);
      owner.setReturnType(IntegerDataType.dataType, SourceType.USER_DEFINED);
      var dormant = createFunction("dormant", 0x1020);
      dormant.updateFunction(
          "__cdecl",
          new ReturnParameterImpl(
              IntegerDataType.dataType, new VariableStorage(real, real.getRegister("EAX")), real),
          Function.FunctionUpdateType.CUSTOM_STORAGE,
          false,
          SourceType.USER_DEFINED,
          new ParameterImpl("saved_input", type, real.getRegister("ECX"), real));
      dormant.getParameter(0).setComment("saved input annotation");
      dormant
          .addLocalVariable(
              new LocalVariableImpl("saved_local", type, -16, real), SourceType.IMPORTED)
          .setComment("saved local annotation");
      dormant.setThunkedFunction(owner);
      createFunction("chain", 0x1040).setThunkedFunction(dormant);
    } finally {
      real.endTransaction(transaction, true);
    }
    var root = state.getProject().getProjectData().getRootFolder();
    var destination = root.getFolder(folder);
    if (destination == null) destination = root.createFolder(folder);
    destination.createFile(name, real, monitor);
  }

  private void configure() throws Exception {
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
    requestMonitor = new TaskMonitorAdapter(true);
    IdentityHashMap<Function, Function> nativeFunctions = new IdentityHashMap<>();
    FunctionManager functions =
        (FunctionManager)
            Proxy.newProxyInstance(
                FunctionManager.class.getClassLoader(),
                new Class<?>[] {FunctionManager.class},
                (proxy, method, args) -> {
                  Object result = invoke(method, real.getFunctionManager(), args);
                  if (!(result instanceof Function function)) return result;
                  Function wrapper =
                      (Function)
                          Proxy.newProxyInstance(
                              Function.class.getClassLoader(),
                              new Class<?>[] {Function.class},
                              (wrapped, operation, inputs) -> {
                                if (operation.getName().equals("setThunkedFunction")
                                    && inputs[0] != null) {
                                  inputs = inputs.clone();
                                  inputs[0] =
                                      nativeFunctions.getOrDefault(inputs[0], (Function) inputs[0]);
                                }
                                Object value = invoke(operation, function, inputs);
                                if (operation.getName().equals("setThunkedFunction")
                                    && inputs[0] == null
                                    && function.getEntryPoint().equals(at(real, 0x1020))) {
                                  if (++clears == cancelAtClear) requestMonitor.cancel();
                                }
                                return value;
                              });
                  nativeFunctions.put(wrapper, function);
                  return wrapper;
                });
    SymbolTable symbols =
        (SymbolTable)
            Proxy.newProxyInstance(
                SymbolTable.class.getClassLoader(),
                new Class<?>[] {SymbolTable.class},
                (proxy, method, args) -> {
                  Object result = invoke(method, real.getSymbolTable(), args);
                  if (cancelVerifyScan
                      && mutationCalls == 1
                      && clears >= 2
                      && method.getName().equals("getSymbol")) {
                    verificationLookups++;
                    cancelVerifyScan = false;
                    requestMonitor.cancel();
                  }
                  return result;
                });
    selected =
        (Program)
            Proxy.newProxyInstance(
                Program.class.getClassLoader(),
                new Class<?>[] {Program.class},
                (proxy, method, args) -> {
                  if (method.getName().equals("getFunctionManager")) return functions;
                  if (method.getName().equals("getSymbolTable")) return symbols;
                  if (method.getName().equals("save")) {
                    saveCalls++;
                    if (savesToFail > 0) {
                      savesToFail--;
                      throw new IOException("injected dormant preview save failure");
                    }
                  }
                  return invoke(method, real, args);
                });
    Class<?> accessClass = loader.loadClass(prefix + "session.ScriptAccess");
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
                case "monitor":
                  return requestMonitor;
                case "state":
                  return state;
                case "logError":
                  printerr((String) args[0]);
                  return null;
                default:
                  throw new UnsupportedOperationException(method.getName());
              }
            });
    Class<?> sessionClass = loader.loadClass(prefix + "session.ProgramSession");
    session = sessionClass.getConstructor(accessClass).newInstance(access);
    Class<?> previewClass = loader.loadClass(prefix + "types.TypeMutationPreview");
    preview = previewClass.getConstructor(sessionClass).newInstance(session);
    executePreview = previewClass.getMethod("execute", Callable.class);
    Class<?> dispatcherClass = loader.loadClass(prefix + "runtime.CommandDispatcher");
    var constructor = dispatcherClass.getDeclaredConstructor(sessionClass);
    constructor.setAccessible(true);
    dispatcher = constructor.newInstance(session);
    executeCommand = dispatcherClass.getDeclaredMethod("execute", String.class, JsonObject.class);
    executeCommand.setAccessible(true);
  }

  private JsonObject command(String name, JsonObject args) throws Exception {
    return (JsonObject) executeCommand.invoke(dispatcher, name, args);
  }

  private JsonObject nativeMutation(String mode) {
    mutationCalls++;
    var type = real.getDataTypeManager().getDataType(TYPE);
    check("baseline".equals(type.getDescription()), "Preview mutation escaped before replay");
    type.setDescription("accepted");
    real.getListing()
        .setComment(at(real, 0x1000), CodeUnit.EOL_COMMENT, "native-call-" + mutationCalls);
    check("accepted".equals(type.getDescription()), "Native type mutation did not execute");
    if (mode.equals("throw")) throw new IllegalStateException("injected native mutation failure");
    JsonObject result = new JsonObject();
    if (mode.equals("error")) result.addProperty("error", "injected returned mutation error");
    else result.addProperty("invocation", mutationCalls);
    return result;
  }

  private JsonObject invokePreview(String mode) throws Exception {
    try {
      return (JsonObject)
          executePreview.invoke(preview, (Callable<JsonObject>) () -> nativeMutation(mode));
    } catch (InvocationTargetException failure) {
      if (failure.getCause() instanceof Exception exception) throw exception;
      if (failure.getCause() instanceof Error error) throw error;
      throw failure;
    }
  }

  private JsonObject functionState(Program program) {
    JsonObject result = new JsonObject();
    var iterator = program.getFunctionManager().getFunctions(true);
    while (iterator.hasNext()) {
      Function function = iterator.next();
      JsonObject row = new JsonObject();
      row.addProperty("id", function.getID());
      row.addProperty("name", function.getName());
      var target = function.getThunkedFunction(false);
      row.addProperty("target", target == null ? null : Long.toString(target.getID()));
      row.addProperty("custom", function.hasCustomVariableStorage());
      row.addProperty("signature_source", function.getSignatureSource().name());
      row.addProperty("calling_convention", function.getCallingConventionName());
      row.addProperty("variadic", function.hasVarArgs());
      row.addProperty("no_return", function.hasNoReturn());
      row.addProperty("stack_purge", function.getStackPurgeSize());
      JsonArray variables = new JsonArray();
      variables.add(variable(program, function.getReturn()));
      for (Variable variable : function.getAllVariables())
        variables.add(variable(program, variable));
      row.add("variables", variables);
      result.add(Long.toString(function.getEntryPoint().getOffset()), row);
    }
    return result;
  }

  private JsonObject variable(Program program, Variable variable) {
    JsonObject result = new JsonObject();
    result.addProperty(
        "id", variable.getSymbol() == null ? null : Long.toString(variable.getSymbol().getID()));
    result.addProperty("name", variable.getName());
    result.addProperty("type", variable.getDataType().getPathName());
    result.addProperty("type_id", program.getDataTypeManager().getID(variable.getDataType()));
    result.addProperty("length", variable.getDataType().getLength());
    result.addProperty("storage", variable.getVariableStorage().toString());
    result.addProperty("valid", variable.isValid());
    result.addProperty("source", variable.getSource().name());
    result.addProperty("comment", variable.getComment());
    return result;
  }

  /**
   * Test-owned native inspection transaction; all inspected values are detached before rollback.
   */
  private JsonObject ownDefinitions() {
    int transaction = real.startTransaction("inspect dormant definitions");
    try {
      var iterator = real.getFunctionManager().getFunctions(true);
      while (iterator.hasNext()) {
        Function function = iterator.next();
        if (function.isThunk()) function.setThunkedFunction(null);
      }
      return functionState(real);
    } finally {
      real.endTransaction(transaction, false);
    }
  }

  private JsonObject persistedState(String description, String marker, String pending)
      throws Exception {
    Object owner = new Object();
    Program saved =
        (Program)
            real.getDomainFile()
                .getReadOnlyDomainObject(owner, DomainFile.DEFAULT_VERSION, TaskMonitor.DUMMY);
    try {
      check(
          description.equals(saved.getDataTypeManager().getDataType(TYPE).getDescription()),
          "Unexpected persisted type description");
      check(
          java.util.Objects.equals(
              marker, saved.getListing().getComment(CodeUnit.EOL_COMMENT, at(saved, 0x1000))),
          "Preview marker escaped into saved database");
      check(
          java.util.Objects.equals(
              pending, saved.getListing().getComment(CodeUnit.PRE_COMMENT, at(saved, 0x1000))),
          "Unexpected persisted pending comment");
      return functionState(saved);
    } finally {
      saved.release(owner);
    }
  }

  private void failedPreview(String mode, JsonObject originalOwn, JsonObject originalSaved)
      throws Exception {
    mutationCalls = 0;
    clears = 0;
    cancelAtClear = mode.equals("edge-cancel") ? 1 : mode.equals("verify-cancel") ? 2 : 0;
    cancelVerifyScan = mode.equals("verify-scan-cancel");
    verificationLookups = 0;
    int previousSaves = saveCalls;
    session
        .getClass()
        .getMethod("beginRequest", String.class)
        .invoke(session, "type_set_description");
    Throwable failure = null;
    JsonObject response = null;
    Object outcome = null;
    try {
      response = invokePreview(mode);
    } catch (Exception exception) {
      failure = exception;
    } finally {
      outcome = session.getClass().getMethod("finishRequest", boolean.class).invoke(session, false);
    }
    check(
        (boolean) outcome.getClass().getMethod("rolledBack").invoke(outcome),
        "Failed preview lacked a completed request rollback");
    check(
        !(boolean) outcome.getClass().getMethod("saved").invoke(outcome),
        "Failed preview was saved");
    check(
        (boolean) outcome.getClass().getMethod("cancelled").invoke(outcome)
            == mode.endsWith("cancel"),
        "Failed preview lost its cancellation receipt");
    if (mode.endsWith("cancel")) {
      check(failure instanceof CancelledException, "Cancellation was not propagated: " + failure);
      if (mode.equals("verify-scan-cancel"))
        check(
            verificationLookups == 1, "Cancellation missed the real native variable verification");
      else check(clears == cancelAtClear, "Cancellation missed the requested native edge phase");
    } else if (mode.equals("throw")) {
      check(
          failure != null && failure.getMessage().contains("injected native mutation failure"),
          "Native mutation failure was lost");
    } else {
      check(
          failure != null || response != null && response.has("error"),
          "Returned mutation error became success");
    }
    check(
        mutationCalls == (mode.equals("edge-cancel") ? 0 : 1),
        "Failed preview executed the production mutation: " + mutationCalls);
    requestMonitor.clearCancelled();
    cancelAtClear = 0;
    check(real.getCurrentTransactionInfo() == null, "Failed preview leaked a transaction");
    check(saveCalls == previousSaves, "Failed preview saved changes");
    check(
        "baseline".equals(real.getDataTypeManager().getDataType(TYPE).getDescription())
            && real.getListing().getComment(CodeUnit.EOL_COMMENT, at(real, 0x1000)) == null,
        "Failed preview retained its native type or comment edits");
    check(originalOwn.equals(ownDefinitions()), "Failed preview changed dormant definitions");
    check(
        originalSaved.equals(persistedState("baseline", null, null)),
        "Failed preview changed persisted function identities");
  }

  private void successPreview(JsonObject originalOwn, JsonObject originalSaved) throws Exception {
    mutationCalls = 0;
    session
        .getClass()
        .getMethod("beginRequest", String.class)
        .invoke(session, "type_set_description");
    JsonObject receipt = invokePreview("success");
    check(
        receipt.get("invocation").getAsInt() == 2 && mutationCalls == 2,
        "Expected one preview and exactly one production mutation: " + receipt);
    Object outcome =
        session.getClass().getMethod("finishRequest", boolean.class).invoke(session, true);
    check((boolean) outcome.getClass().getMethod("saved").invoke(outcome), "Missing save receipt");
    check(
        !(boolean) outcome.getClass().getMethod("rolledBack").invoke(outcome),
        "Success rolled back");
    check(saveCalls == 1, "Successful native mutation saved more than once");
    check(originalOwn.equals(ownDefinitions()), "Success changed unrelated dormant definitions");
    check(
        originalSaved.equals(persistedState("accepted", "native-call-2", null)),
        "Success persisted a preview edge or variable change");
  }

  private void saveRecovery(JsonObject originalOwn, JsonObject originalSaved) throws Exception {
    JsonObject comment = new JsonObject();
    comment.addProperty("address", "0x1000");
    comment.addProperty("comment_type", "PRE");
    comment.addProperty("text", "pending-before-preview");
    savesToFail = 1;
    JsonObject pending = command("comment_set", comment);
    check(pending.getAsJsonObject("detail").get("save_failed").getAsBoolean(), pending.toString());
    int previousSaves = saveCalls;
    failedPreview("error", originalOwn, originalSaved);
    check(
        "pending-before-preview"
            .equals(real.getListing().getComment(CodeUnit.PRE_COMMENT, at(real, 0x1000))),
        "Failed preview lost earlier pending edit");
    check(saveCalls == previousSaves, "Failed preview saved earlier pending edit");
    JsonObject args = new JsonObject();
    args.addProperty("type_name", TYPE);
    args.addProperty("offset", 0);
    args.addProperty("field_type", "int");
    args.addProperty("field_name", "accepted_field");
    savesToFail = 1;
    int clearsBefore = clears;
    JsonObject response = command("type_field_set", args);
    JsonObject detail = response.getAsJsonObject("detail");
    check(
        "error".equals(response.get("status").getAsString())
            && detail.get("save_failed").getAsBoolean()
            && !detail.get("saved").getAsBoolean(),
        response.toString());
    JsonObject receipt = detail.getAsJsonObject("command_response").getAsJsonObject("data");
    check(
        receipt.get("changed").getAsBoolean()
            && "accepted_field".equals(receipt.getAsJsonObject("after").get("name").getAsString()),
        "Save failure lost the successful native type mutation receipt: " + response);
    check(clears == clearsBefore + 2, "Dispatcher type mutation bypassed dormant preview");
    check(saveCalls == previousSaves + 1, "Save failure retried mutation/save");
    check(
        real.isChanged()
            && "accepted_field"
                .equals(
                    ((Structure) real.getDataTypeManager().getDataType(TYPE))
                        .getComponentAt(0)
                        .getFieldName()),
        "Save failure lost pending native type edit");
    check(originalOwn.equals(ownDefinitions()), "Save failure retained preview dormant state");
    check(
        originalSaved.equals(persistedState("baseline", null, null)),
        "Save failure changed persisted native state");
    persistedField(false);
    JsonObject saved = command("program_save", new JsonObject());
    check("success".equals(saved.get("status").getAsString()), saved.toString());
    check(saveCalls == previousSaves + 2, "Explicit recovery save did not run exactly once");
    check(
        originalSaved.equals(persistedState("baseline", null, "pending-before-preview")),
        "Recovery saved preview state instead of retained production edits");
    persistedField(true);
  }

  private void persistedField(boolean expected) throws Exception {
    Object owner = new Object();
    Program saved =
        (Program)
            real.getDomainFile()
                .getReadOnlyDomainObject(owner, DomainFile.DEFAULT_VERSION, TaskMonitor.DUMMY);
    try {
      Structure type = (Structure) saved.getDataTypeManager().getDataType(TYPE);
      check(
          expected == "accepted_field".equals(type.getComponentAt(0).getFieldName()),
          "Unexpected persisted native field mutation");
    } finally {
      saved.release(owner);
    }
  }

  public void run() throws Exception {
    if (getScriptArgs().length == 2 && getScriptArgs()[1].equals("inspect")) {
      Function function =
          currentProgram.getFunctionManager().getFunctionAt(at(currentProgram, 0x1020));
      check(!function.isThunk(), "Inspection must expose the reopened own definition");
      var parameter = function.getParameter(0);
      check(
          parameter != null
              && parameter.isValid()
              && TYPE.equals(parameter.getDataType().getPathName())
              && parameter.getDataType().getLength() == 4
              && "saved input annotation".equals(parameter.getComment()),
          "Reopened own parameter changed");
      boolean found = false;
      for (Variable local : function.getLocalVariables()) {
        if (local.getName().equals("saved_local")) {
          found =
              local.isValid()
                  && TYPE.equals(local.getDataType().getPathName())
                  && local.getDataType().getLength() == 4
                  && "saved local annotation".equals(local.getComment());
        }
      }
      check(found, "Reopened own local changed");
      println("dormant-preview-reopened-ok");
      return;
    }
    for (String mode :
        new String[] {
          "edge-cancel",
          "verify-cancel",
          "verify-scan-cancel",
          "error",
          "throw",
          "success",
          "save-recovery"
        }) {
      saveCalls = savesToFail = mutationCalls = clears = cancelAtClear = 0;
      session = null;
      createProgram(getScriptArgs()[0], mode);
      try {
        configure();
        JsonObject own = ownDefinitions();
        JsonObject saved = persistedState("baseline", null, null);
        if (mode.equals("success")) successPreview(own, saved);
        else if (mode.equals("save-recovery")) saveRecovery(own, saved);
        else failedPreview(mode, own, saved);
        println("dormant-preview-ok:" + mode);
      } finally {
        cancelAtClear = savesToFail = 0;
        cancelVerifyScan = false;
        if (requestMonitor != null) requestMonitor.clearCancelled();
        try {
          if (session != null) session.getClass().getMethod("closeProgram").invoke(session);
        } finally {
          real.release(this);
        }
      }
    }
  }
}
