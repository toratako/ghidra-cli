import com.google.gson.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.util.TreeMap;

/** Independent saved return, parameter and local applications for each mutation boundary. */
public class SavedVariablePropagationFixture extends GhidraScript {
  private Function function(String name, long offset) throws Exception {
    var entry = toAddr(offset);
    return currentProgram
        .getFunctionManager()
        .createFunction(name, entry, new AddressSet(entry), SourceType.USER_DEFINED);
  }

  private DataType structure(String name, int length) {
    return currentProgram
        .getDataTypeManager()
        .addDataType(new StructureDataType(new CategoryPath("/Audit"), name, length), null);
  }

  private void custom(Function function, DataType type, String kind) throws Exception {
    var result =
        new ReturnParameterImpl(
            kind.equals("Return") ? type : IntegerDataType.dataType,
            new VariableStorage(currentProgram, currentProgram.getRegister("EAX")),
            currentProgram);
    var inputs =
        kind.equals("Parameter")
            ? new Parameter[] {
              new ParameterImpl("input", type, currentProgram.getRegister("ECX"), currentProgram)
            }
            : new Parameter[0];
    function.updateFunction(
        "__cdecl",
        result,
        Function.FunctionUpdateType.CUSTOM_STORAGE,
        false,
        SourceType.USER_DEFINED,
        inputs);
    if (kind.equals("Parameter")) function.getParameter(0).setComment("saved input");
    if (kind.equals("Local")) {
      var local =
          function.addLocalVariable(
              new LocalVariableImpl("saved_local", type, -32, currentProgram),
              SourceType.USER_DEFINED);
      local.setComment("saved local");
      function
          .addLocalVariable(
              new LocalVariableImpl("neighbor", IntegerDataType.dataType, -8, currentProgram),
              SourceType.IMPORTED)
          .setComment("untouched neighbor");
    }
  }

  public void run() throws Exception {
    if (getScriptArgs()[0].equals("create")) {
      var dtm = currentProgram.getDataTypeManager();
      currentProgram
          .getMemory()
          .createInitializedBlock("code", toAddr(0x1000), 0x200, (byte) 0, monitor, false);
      int index = 0;
      for (String operation : new String[] {"Resize", "Field", "Import"}) {
        for (String kind : new String[] {"Return", "Parameter", "Local"}) {
          String name = operation + kind;
          DataType type = structure(name, 4);
          if (kind.equals("Parameter"))
            type =
                dtm.addDataType(
                    new TypedefDataType(new CategoryPath("/Audit"), name + "Alias", type), null);
          if (kind.equals("Local")) type = dtm.addDataType(new ArrayDataType(type, 2, 4), null);
          Function function;
          if (name.equals("ImportReturn"))
            function =
                currentProgram
                    .getExternalManager()
                    .addExtFunction("library", name, null, SourceType.IMPORTED)
                    .getFunction();
          else
            function = function(name, name.equals("ImportLocal") ? 0x9000 : 0x1000 + index * 0x10);
          custom(function, type, kind);
          index++;
        }
      }
      function("wrapper", 0x1100).setThunkedFunction(getFunctionAt(toAddr(0x1000)));
      var dynamic = function("dynamic", 0x1120);
      var dynamicType = structure("DynamicValue", 4);
      dynamic.updateFunction(
          "__cdecl",
          new ReturnParameterImpl(dynamicType, currentProgram),
          Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS,
          false,
          SourceType.USER_DEFINED,
          new ParameterImpl("input", dynamicType, currentProgram));
      custom(function("pointer", 0x1160), new PointerDataType(dynamicType), "Parameter");
      var invalidType = (Structure) structure("PreexistingInvalid", 4);
      custom(function("preexisting_invalid", 0x1140), invalidType, "Parameter");
      invalidType.setLength(8);
      structure("Unreferenced", 4);
      return;
    }
    TreeMap<String, JsonObject> rows = new TreeMap<>();
    var symbols = currentProgram.getSymbolTable().getSymbols(null, SymbolType.FUNCTION, true);
    while (symbols.hasNext()) {
      var function = currentProgram.getFunctionManager().getFunction(symbols.next().getID());
      JsonObject row = new JsonObject();
      row.addProperty("id", function.getID());
      row.addProperty("name", function.getName());
      row.addProperty("custom", function.hasCustomVariableStorage());
      row.addProperty("source", function.getSignatureSource().name());
      JsonArray variables = new JsonArray();
      variables.add(variable("return", function.getReturn()));
      for (var parameter : function.getParameters())
        variables.add(variable("parameter", parameter));
      for (var local : function.getLocalVariables()) variables.add(variable("local", local));
      row.add("variables", variables);
      rows.put(function.getName(), row);
    }
    println(new Gson().toJson(rows));
  }

  private JsonObject variable(String kind, Variable variable) {
    JsonObject row = new JsonObject();
    row.addProperty("kind", kind);
    row.addProperty("id", variable.getSymbol() == null ? null : variable.getSymbol().getID());
    row.addProperty("name", variable.getName());
    row.addProperty("type", variable.getDataType().getPathName());
    row.addProperty("length", variable.getDataType().getLength());
    if (variable instanceof Parameter parameter)
      row.addProperty("formal_type", parameter.getFormalDataType().getPathName());
    row.addProperty("storage", variable.getVariableStorage().toString());
    row.addProperty("storage_length", variable.getVariableStorage().size());
    row.addProperty("valid", variable.isValid());
    row.addProperty("source", variable.getSource().name());
    row.addProperty("comment", variable.getComment());
    return row;
  }
}
