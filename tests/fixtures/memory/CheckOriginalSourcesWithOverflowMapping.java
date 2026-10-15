import com.google.gson.JsonObject;
import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.util.task.TaskMonitor;
import java.io.ByteArrayInputStream;
import java.lang.reflect.Proxy;

/** An unusable indirect source must not prevent inspection of direct preserved file bytes. */
public class CheckOriginalSourcesWithOverflowMapping extends GhidraScript {
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
    var language = currentProgram.getLanguage();
    Object consumer = new Object();
    var program =
        new ProgramDB(
            "overflow-file-source", language, language.getDefaultCompilerSpec(), consumer);
    int transaction = program.startTransaction("create native indirect overflow");
    Object sessionConsumer = null;
    try {
      var memory = program.getMemory();
      var space = program.getAddressFactory().getDefaultAddressSpace();
      Address direct = space.getAddress(0x1000);
      byte[] original = {0x10, 0x11, 0x12, 0x13};
      var file =
          memory.createFileBytes(
              "preserved", 0x200, original.length, new ByteArrayInputStream(original), monitor);
      memory.createInitializedBlock("direct", direct, file, 0, original.length, false);
      var bits =
          memory.createBitMappedBlock(
              "bits", space.getAddress(0x2000), space.getMaxAddress(), 8, false);
      var expanded = memory.createBlock(bits, "expanded", space.getAddress(0x3000), 16);
      try {
        expanded.getSourceInfos().get(0).getMappedRange();
        throw new IllegalStateException("Fixture did not create the native mapped source overflow");
      } catch (AddressOutOfBoundsException expected) {
        // The public clone API accepts the block, but its mapped range cannot be represented.
      }

      Class<?> accessClass = loader.loadClass(prefix + "session.ScriptAccess");
      Object access =
          Proxy.newProxyInstance(
              loader,
              new Class<?>[] {accessClass},
              (proxy, method, args) -> {
                switch (method.getName()) {
                  case "program":
                    return program;
                  case "monitor":
                    return TaskMonitor.DUMMY;
                  default:
                    throw new UnsupportedOperationException(method.getName());
                }
              });
      Class<?> sessionClass = loader.loadClass(prefix + "session.ProgramSession");
      Object session = sessionClass.getConstructor(accessClass).newInstance(access);
      var owner = sessionClass.getDeclaredField("consumer");
      owner.setAccessible(true);
      sessionConsumer = owner.get(session);
      Class<?> sources = loader.loadClass(prefix + "memory.MemorySources");
      var describe = sources.getDeclaredMethod("describe", sessionClass, Address.class);
      describe.setAccessible(true);
      JsonObject description = (JsonObject) describe.invoke(null, session, direct);
      if (!description.get("state").getAsString().equals("mapped")
          || description.get("file_offset").getAsLong() != 0x200) {
        throw new IllegalStateException("Direct provenance was lost: " + description);
      }
      JsonObject indirect = (JsonObject) describe.invoke(null, session, expanded.getStart());
      if (!indirect.get("state").getAsString().equals("unsupported")) {
        throw new IllegalStateException(
            "Overflowing indirect source was not excluded: " + indirect);
      }

      var read = sources.getDeclaredMethod("readOriginal", sessionClass, Address.class, int.class);
      read.setAccessible(true);
      Object bytes = read.invoke(null, session, direct, original.length);
      var hex = bytes.getClass().getDeclaredMethod("hex");
      hex.setAccessible(true);
      if (!hex.invoke(bytes).equals("10111213")) {
        throw new IllegalStateException("Unrelated indirect mapping changed the original read");
      }

      var mappings =
          sources.getDeclaredMethod("fileMappings", sessionClass, Long.class, Address.class);
      mappings.setAccessible(true);
      JsonObject reverse = (JsonObject) mappings.invoke(null, session, Long.valueOf(0x201), null);
      if (reverse.get("count").getAsInt() != 1
          || reverse.getAsJsonArray("unsupported_mappings").size() != 2
          || reverse
                  .getAsJsonArray("mappings")
                  .get(0)
                  .getAsJsonObject()
                  .get("file_bytes_offset")
                  .getAsLong()
              != 1) {
        throw new IllegalStateException("Direct reverse mapping was lost: " + reverse);
      }
    } finally {
      try {
        program.endTransaction(transaction, false);
      } finally {
        if (sessionConsumer != null) program.release(sessionConsumer);
        program.release(consumer);
      }
    }
  }
}
