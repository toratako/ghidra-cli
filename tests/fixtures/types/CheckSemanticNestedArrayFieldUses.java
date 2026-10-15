import com.google.gson.JsonArray;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import java.lang.reflect.Proxy;

/** Native two-dimensional field access retains the identity of its containing member. */
public class CheckSemanticNestedArrayFieldUses extends GhidraScript {
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
    Class<?> sessionClass = loader.loadClass(prefix + "session.ProgramSession");
    Class<?> accessClass = loader.loadClass(prefix + "session.ScriptAccess");
    var language =
        DefaultLanguageService.getLanguageService()
            .getLanguage(new LanguageID("x86:LE:32:default"));
    ProgramDB program =
        new ProgramDB("nested-array-fields", language, language.getDefaultCompilerSpec(), this);
    DecompInterface engine = new DecompInterface();
    try {
      Function function;
      Structure packet;
      int transaction = program.startTransaction("nested array field fixture");
      try {
        var manager = program.getDataTypeManager();
        var row = new ArrayDataType(IntegerDataType.dataType, 3, 4, manager);
        var matrix = new ArrayDataType(row, 2, row.getLength(), manager);
        var definition = new StructureDataType("MatrixPacket", 8, manager);
        definition.add(matrix, "matrix", null);
        packet = (Structure) manager.addDataType(definition, null);
        var entry = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000);
        // return ctx->matrix[row][column];
        int[] bytes = {
          0x8b, 0x44, 0x24, 0x04, 0x8b, 0x54, 0x24, 0x08, 0x8d, 0x14, 0x52, 0x8b, 0x4c, 0x24, 0x0c,
          0x01, 0xca, 0x8b, 0x44, 0x90, 0x08, 0xc3
        };
        byte[] code = new byte[bytes.length];
        for (int i = 0; i < bytes.length; i++) code[i] = (byte) bytes[i];
        var block =
            program
                .getMemory()
                .createInitializedBlock("code", entry, code.length, (byte) 0, monitor, false);
        block.setExecute(true);
        program.getMemory().setBytes(entry, code);
        var body = new AddressSet(entry, entry.add(code.length - 1));
        if (!new DisassembleCommand(entry, body, true).applyTo(program, monitor)) {
          throw new IllegalStateException("Cannot disassemble nested array access");
        }
        function =
            program
                .getFunctionManager()
                .createFunction("read_matrix", entry, body, SourceType.USER_DEFINED);
        function.setCallingConvention("__cdecl");
        function.setReturnType(IntegerDataType.dataType, SourceType.USER_DEFINED);
        function.addParameter(
            new ParameterImpl("ctx", new PointerDataType(packet, 4, manager), program),
            SourceType.USER_DEFINED);
        function.addParameter(
            new ParameterImpl("row", IntegerDataType.dataType, program), SourceType.USER_DEFINED);
        function.addParameter(
            new ParameterImpl("column", IntegerDataType.dataType, program),
            SourceType.USER_DEFINED);
      } finally {
        program.endTransaction(transaction, true);
      }
      Object access =
          Proxy.newProxyInstance(
              loader,
              new Class<?>[] {accessClass},
              (proxy, method, args) -> {
                switch (method.getName()) {
                  case "program":
                    return program;
                  case "monitor":
                    return monitor;
                  default:
                    throw new UnsupportedOperationException(method.getName());
                }
              });
      Object session = sessionClass.getConstructor(accessClass).newInstance(access);
      Class<?> fieldsClass = loader.loadClass(prefix + "analysis.FieldUses");
      var find =
          fieldsClass.getDeclaredMethod(
              "find",
              sessionClass,
              Function.class,
              DecompileResults.class,
              ghidra.program.model.data.DataTypeComponent.class);
      find.setAccessible(true);
      long modification = program.getModificationNumber();
      if (!engine.openProgram(program)) throw new IllegalStateException("Cannot open decompiler");
      DecompileResults results = engine.decompileFunction(function, 30, monitor);
      if (!results.decompileCompleted()) throw new IllegalStateException(results.getErrorMessage());
      Object findings = find.invoke(null, session, function, results, packet.getComponentAt(8));
      var usesMethod = findings.getClass().getDeclaredMethod("uses");
      usesMethod.setAccessible(true);
      var unresolvedMethod = findings.getClass().getDeclaredMethod("unresolved");
      unresolvedMethod.setAccessible(true);
      JsonArray uses = (JsonArray) usesMethod.invoke(findings);
      if (uses.size() != 1
          || !uses.get(0).getAsJsonObject().get("access").getAsString().equals("read")
          || !((JsonArray) unresolvedMethod.invoke(findings)).isEmpty()) {
        StringBuilder operations = new StringBuilder();
        results
            .getHighFunction()
            .getPcodeOps()
            .forEachRemaining(op -> operations.append(op).append('\n'));
        throw new IllegalStateException(
            "Nested array read lost field identity: "
                + uses
                + "\n"
                + results.getDecompiledFunction().getC()
                + "\n"
                + operations);
      }
      // Replacing the outer stride with an incompatible cast/index must not
      // become a proven read merely because the final subscript still uses 4.
      var high = results.getHighFunction();
      var operations = high.getPcodeOps();
      boolean replaced = false;
      while (operations.hasNext()) {
        PcodeOp op = operations.next();
        if (op.getOpcode() == PcodeOp.PTRADD && op.getInput(2).getOffset() == 12) {
          high.setInput(
              op, high.newVarnode(4, high.getAddressFactory().getConstantSpace().getAddress(8)), 2);
          replaced = true;
          break;
        }
      }
      if (!replaced) throw new IllegalStateException("Missing native outer array stride");
      findings = find.invoke(null, session, function, results, packet.getComponentAt(8));
      uses = (JsonArray) usesMethod.invoke(findings);
      JsonArray unresolved = (JsonArray) unresolvedMethod.invoke(findings);
      if (uses.size() != 1
          || !uses.get(0).getAsJsonObject().get("access").getAsString().equals("address")
          || unresolved.isEmpty()) {
        throw new IllegalStateException(
            "Incompatible array stride proved a read: " + uses + " " + unresolved);
      }
      if (program.getModificationNumber() != modification) {
        throw new IllegalStateException("Semantic array search changed the program");
      }
    } finally {
      engine.dispose();
      program.release(this);
    }
  }
}
