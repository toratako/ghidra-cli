import com.google.gson.JsonObject;
import ghidra.app.script.GhidraScript;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;

/** Bound closure work and surface native instruction recursion as a test failure. */
public class CheckMappedReadBounds extends GhidraScript {
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
    boolean instructionMode =
        getScriptArgs().length > 0 && getScriptArgs()[0].equals("instruction");
    boolean definitionMode = getScriptArgs().length > 0 && getScriptArgs()[0].equals("definition");
    Object reader = new Object();
    Program source =
        instructionMode
            ? (Program)
                currentProgram
                    .getDomainFile()
                    .getReadOnlyDomainObject(reader, DomainFile.DEFAULT_VERSION, TaskMonitor.DUMMY)
            : currentProgram;
    // Borrow the script's Program for reads. The probe session owns only its
    // added consumer, never the caller's script transaction or saving.
    Program readOnly =
        (Program)
            Proxy.newProxyInstance(
                Program.class.getClassLoader(),
                new Class<?>[] {Program.class},
                (proxy, method, args) -> {
                  if (method.getName().equals("getCurrentTransactionInfo")) return null;
                  if (method.getName().equals("isChanged")) return false;
                  try {
                    return method.invoke(source, args);
                  } catch (InvocationTargetException failure) {
                    throw failure.getCause();
                  }
                });
    Program[] selected = {readOnly};
    TaskMonitorAdapter bounded =
        new TaskMonitorAdapter(true) {
          int checks;

          @Override
          public void checkCancelled() throws CancelledException {
            if (++checks == 2000 && !instructionMode && !definitionMode) cancel();
            super.checkCancelled();
          }
        };
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
                  return bounded;
                default:
                  throw new UnsupportedOperationException(method.getName());
              }
            });
    Class<?> sessionClass = loader.loadClass(prefix + "session.ProgramSession");
    Object session = sessionClass.getConstructor(accessClass).newInstance(access);
    try {
      if (instructionMode) {
        Class<?> listingClass = loader.loadClass(prefix + "listing.InstructionListing");
        Object listing = listingClass.getConstructor(sessionClass).newInstance(session);
        JsonObject found;
        try {
          AddressSet locations = new AddressSet(toAddr(0xc000));
          found =
              (JsonObject)
                  listingClass
                      .getMethod("instructionsIn", AddressSetView.class, JsonObject.class)
                      .invoke(listing, locations, new JsonObject());
        } catch (InvocationTargetException failure) {
          throw new IllegalStateException(
              "Mapped instruction byte reader failed: "
                  + failure.getCause().getClass().getSimpleName());
        }
        if (found.get("count").getAsInt() != 1
            || !found
                .getAsJsonArray("instructions")
                .get(0)
                .getAsJsonObject()
                .get("bytes")
                .getAsString()
                .equals("c3"))
          throw new IllegalStateException("Wrong mapped instruction bytes: " + found);
        var savedData = source.getListing().getDefinedDataAt(toAddr(0x11000));
        if (savedData == null
            || savedData.getLength() != 1
            || !savedData.getDataType().getName().equals("byte"))
          throw new IllegalStateException(
              "Saved definition changed after failed force replacement");
        return;
      }
      Class<?> resolverClass = loader.loadClass(prefix + "query.AddressResolver");
      Object resolver = resolverClass.getConstructor(sessionClass).newInstance(session);
      Class<?> stringsClass = loader.loadClass(prefix + "listing.StringQueries");
      Object strings = stringsClass.getConstructor(sessionClass).newInstance(session);
      if (definitionMode) {
        Class<?> instructionClass = loader.loadClass(prefix + "listing.InstructionListing");
        Object instructions = instructionClass.getConstructor(sessionClass).newInstance(session);
        Class<?> typesClass = loader.loadClass(prefix + "types.TypeResolver");
        Object types = typesClass.getConstructor(sessionClass).newInstance(session);
        Class<?> listingClass = loader.loadClass(prefix + "listing.ListingCommands");
        Object listing =
            listingClass
                .getConstructor(
                    sessionClass, resolverClass, stringsClass, instructionClass, typesClass)
                .newInstance(session, resolver, strings, instructions, types);
        JsonObject args = new JsonObject();
        args.addProperty("address", "0x11000");
        args.addProperty("type_name", "TerminatedCString");
        args.addProperty("force", true);
        JsonObject response;
        try {
          response =
              (JsonObject)
                  listingClass
                      .getMethod("handleDefineData", JsonObject.class)
                      .invoke(listing, args);
        } catch (InvocationTargetException failure) {
          throw new IllegalStateException(
              "Native definition escaped request failure: "
                  + failure.getCause().getClass().getSimpleName());
        }
        if (!response.has("error")
            || !source
                .getListing()
                .getDefinedDataAt(toAddr(0x11000))
                .getDataType()
                .getName()
                .equals("byte"))
          throw new IllegalStateException(
              "Definition failed without preserving existing data: " + response);
        return;
      }
      Class<?> searchClass = loader.loadClass(prefix + "listing.SearchCommands");
      Object search =
          searchClass
              .getConstructor(sessionClass, resolverClass, stringsClass)
              .newInstance(session, resolver, strings);
      JsonObject args = new JsonObject();
      args.addProperty("hex", "5a");
      args.addProperty("limit", 1);
      JsonObject found =
          (JsonObject)
              searchClass.getMethod("handleFindBytes", JsonObject.class).invoke(search, args);
      if (bounded.isCancelled()
          || found.has("error")
          || found.get("count").getAsInt() != 1
          || !found
              .getAsJsonArray("results")
              .get(0)
              .getAsJsonObject()
              .get("address")
              .getAsString()
              .equals("0x00001000")) {
        throw new IllegalStateException(
            "Early search exhausted the mapped-closure work budget: " + found);
      }
      Class<?> readsClass = loader.loadClass(prefix + "memory.MemoryReads");
      Object reads = readsClass.getConstructor(sessionClass).newInstance(session);
      AddressSetView initialized =
          (AddressSetView) readsClass.getMethod("initializedAddresses").invoke(reads);
      for (int offset = 0; offset < 5; offset++) {
        if (initialized.contains(toAddr(0x7000000 + offset)) != (offset % 2 == 0))
          throw new IllegalStateException(
              "Self-shift closure filled an unreadable residue at " + offset);
      }
    } finally {
      bounded.clearCancelled();
      try {
        sessionClass.getMethod("closeProgram").invoke(session);
      } finally {
        if (instructionMode) source.release(reader);
      }
    }
  }
}
