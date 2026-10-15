import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import java.lang.reflect.InvocationTargetException;
import java.util.function.Supplier;

public class CreateDeepCallThunks extends GhidraScript {
  private void checkFunctionMetadataFailureBoundary() throws Exception {
    ClassLoader loader =
        StackWalker.getInstance(StackWalker.Option.RETAIN_CLASS_REFERENCE)
            .walk(
                frames ->
                    frames
                        .map(StackWalker.StackFrame::getDeclaringClass)
                        .filter(
                            type ->
                                type.getName()
                                    .equals(
                                        String.join(".", "ghidracli", "script", "ScriptCommands")))
                        .findFirst()
                        .orElseThrow())
            .getClassLoader();
    var metadata =
        loader
            .loadClass(String.join(".", "ghidracli", "analysis", "CallReferences"))
            .getDeclaredMethod("readFunctionMetadata", Supplier.class);
    metadata.setAccessible(true);
    StackOverflowError overflow = new StackOverflowError("Function metadata overflow probe");
    try {
      metadata.invoke(
          null,
          (Supplier<Object>)
              () -> {
                throw overflow;
              });
      throw new IllegalStateException("Function metadata failure was not propagated");
    } catch (InvocationTargetException wrapped) {
      Throwable failure = wrapped.getCause();
      if (!(failure instanceof IllegalArgumentException) || failure.getCause() != overflow) {
        throw new IllegalStateException("Function metadata failure was not converted", failure);
      }
      String message = failure.getMessage();
      if (message == null
          || !message.contains("recursive thunk chain")
          || !message.contains("ghidra-cli program close")
          || !message.contains("ghidra-cli program open")) {
        throw new IllegalStateException(
            "Function metadata failure lacks recovery commands", failure);
      }
    }
  }

  public void run() throws Exception {
    // Exercise the guard independently of native stack capacity and JIT compilation.
    checkFunctionMetadataFailureBoundary();
    var language =
        DefaultLanguageService.getLanguageService()
            .getLanguage(new LanguageID("x86:LE:64:default"));
    var program =
        new ProgramDB(getScriptArgs()[0], language, language.getDefaultCompilerSpec(), this);
    try {
      int tx = program.startTransaction("deep call thunks");
      try {
        var space = program.getAddressFactory().getDefaultAddressSpace();
        var source = SourceType.USER_DEFINED;
        program
            .getMemory()
            .createInitializedBlock(
                "code", space.getAddress(0x1000), 0x4003, (byte) 0, monitor, false);
        Function[] functions = new Function[8192];
        for (int i = 0; i < functions.length; i++) {
          var entry = space.getAddress(0x2000 + i);
          functions[i] =
              program
                  .getFunctionManager()
                  .createFunction(
                      i == functions.length - 1 ? "deep_root" : "deep_thunk_" + i,
                      entry,
                      new AddressSet(entry, entry),
                      source);
        }
        // Set each edge before its destination becomes a thunk, keeping fixture setup linear.
        for (int i = 0; i < functions.length - 1; i++) {
          functions[i].setThunkedFunction(functions[i + 1]);
        }
        // Keep the first thunk before its caller so whole-program iteration loads it first.
        var site = space.getAddress(0x5000);
        var body = new AddressSet(site, site.add(2));
        program.getMemory().setBytes(site, new byte[] {(byte) 0xff, (byte) 0xd0, (byte) 0xc3});
        if (!new DisassembleCommand(site, body, false).applyTo(program, monitor)) {
          throw new IllegalStateException("Cannot disassemble deep thunk caller");
        }
        program.getFunctionManager().createFunction("deep_caller", site, body, source);
        program
            .getReferenceManager()
            .addMemoryReference(
                site, functions[0].getEntryPoint(), RefType.COMPUTED_CALL, source, 0);
      } finally {
        program.endTransaction(tx, true);
      }
      state
          .getProject()
          .getProjectData()
          .getRootFolder()
          .createFile(getScriptArgs()[0], program, monitor);
    } finally {
      program.release(this);
    }
  }
}
