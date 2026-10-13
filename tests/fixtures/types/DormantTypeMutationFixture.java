import com.google.gson.*;
import ghidra.app.script.GhidraScript;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.task.TaskMonitor;
import java.util.*;

/** Independent dormant value types, public-API own views, and saved graph snapshots. */
public class DormantTypeMutationFixture extends GhidraScript {
  private long nextAddress = 0x1000;
  private final CategoryPath category = new CategoryPath("/Dormant");

  private DataType structure(String name, int size) {
    return currentProgram
        .getDataTypeManager()
        .addDataType(new StructureDataType(category, name, size), null);
  }

  private Function function(String name) throws Exception {
    var address = toAddr(nextAddress);
    nextAddress += 0x10;
    var result =
        currentProgram
            .getFunctionManager()
            .createFunction(name, address, new AddressSet(address), SourceType.USER_DEFINED);
    result.setComment("preserved function " + name);
    result.setRepeatableComment("preserved repeatable " + name);
    return result;
  }

  private void apply(
      Function function,
      boolean custom,
      DataType returns,
      DataType parameter,
      DataType local,
      String convention)
      throws Exception {
    Parameter result =
        custom
            ? new ReturnParameterImpl(
                returns,
                new VariableStorage(currentProgram, currentProgram.getRegister("EAX")),
                currentProgram)
            : new ReturnParameterImpl(returns, currentProgram);
    Parameter input =
        custom
            ? new ParameterImpl(
                "saved_input", parameter, currentProgram.getRegister("ECX"), currentProgram)
            : new ParameterImpl("saved_input", parameter, currentProgram);
    function.updateFunction(
        convention,
        result,
        custom
            ? Function.FunctionUpdateType.CUSTOM_STORAGE
            : Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS,
        false,
        SourceType.USER_DEFINED,
        input);
    for (Parameter value : function.getParameters()) {
      if (!value.isAutoParameter() && value.getName().equals("saved_input"))
        value.setComment("preserved input " + function.getName());
    }
    if (!function.isExternal()) {
      function
          .addLocalVariable(
              new LocalVariableImpl("saved_local", local, -64, currentProgram),
              SourceType.USER_DEFINED)
          .setComment("preserved local " + function.getName());
      function
          .addLocalVariable(
              new LocalVariableImpl("neighbor", IntegerDataType.dataType, -8, currentProgram),
              SourceType.IMPORTED)
          .setComment("preserved neighbor " + function.getName());
    }
  }

  private Function owner(String name, boolean custom) throws Exception {
    Function result = function(name);
    DataType type = structure(name + "Value", 4);
    apply(result, custom, type, type, IntegerDataType.dataType, "__stdcall");
    return result;
  }

  private DataType array(DataType type) {
    return currentProgram
        .getDataTypeManager()
        .addDataType(new ArrayDataType(type, 2, type.getLength()), null);
  }

  private void create() throws Exception {
    var dtm = currentProgram.getDataTypeManager();
    currentProgram
        .getMemory()
        .createInitializedBlock("code", toAddr(0x1000), 0x2000, (byte) 0, monitor, false);
    for (String operation : new String[] {"Resize", "Field", "Import"}) {
      for (String kind : new String[] {"Return", "Parameter", "Local"}) {
        String name = operation + kind;
        DataType type = structure(name, 4);
        if (kind.equals("Parameter"))
          type = dtm.addDataType(new TypedefDataType(category, name + "Alias", type), null);
        if (kind.equals("Local")) type = array(type);
        Function own = function(name);
        apply(
            own,
            true,
            kind.equals("Return") ? type : IntegerDataType.dataType,
            kind.equals("Parameter") ? type : IntegerDataType.dataType,
            kind.equals("Local") ? type : IntegerDataType.dataType,
            "__cdecl");
        own.setThunkedFunction(owner(name + "Owner", true));
      }
    }
    for (boolean ownCustom : new boolean[] {true, false}) {
      for (boolean ownerCustom : new boolean[] {true, false}) {
        String name = "Mode" + (ownCustom ? "C" : "D") + (ownerCustom ? "C" : "D");
        DataType type = structure(name + "Value", 4);
        Function own = function(name);
        apply(
            own,
            ownCustom,
            ownCustom ? IntegerDataType.dataType : type,
            ownCustom ? IntegerDataType.dataType : type,
            ownCustom ? array(type) : IntegerDataType.dataType,
            "__cdecl");
        own.setThunkedFunction(owner(name + "Owner", ownerCustom));
      }
    }
    DataType dynamicType = structure("DynamicValue", 4);
    Function dynamic = function("Dynamic");
    apply(dynamic, false, dynamicType, dynamicType, IntegerDataType.dataType, "__cdecl");
    dynamic.setThunkedFunction(owner("DynamicOwner", true));

    DataType pointerType = structure("PointerValue", 4);
    Function pointer = function("Pointer");
    apply(
        pointer,
        true,
        IntegerDataType.dataType,
        new PointerDataType(pointerType, dtm),
        IntegerDataType.dataType,
        "__cdecl");
    pointer.setThunkedFunction(owner("PointerOwner", false));

    Structure invalidType = (Structure) structure("PreexistingInvalid", 4);
    Function invalid = function("Preexisting");
    apply(
        invalid, true, IntegerDataType.dataType, invalidType, IntegerDataType.dataType, "__cdecl");
    invalidType.setLength(8);
    invalid.setThunkedFunction(owner("PreexistingOwner", true));
    structure("Unreferenced", 4);

    DataType kindType = structure("KindValue", 4);
    Function kind = function("KindReturn");
    apply(kind, true, kindType, IntegerDataType.dataType, IntegerDataType.dataType, "__cdecl");
    kind.setThunkedFunction(owner("KindOwner", true));

    DataType chainType = structure("ChainValue", 4);
    Function chained = function("Chained");
    apply(
        chained,
        true,
        IntegerDataType.dataType,
        IntegerDataType.dataType,
        array(chainType),
        "__cdecl");
    Function middle = owner("Middle", false);
    Function external =
        currentProgram
            .getExternalManager()
            .addExtFunction("library", "ExternalOwner", null, SourceType.IMPORTED)
            .getFunction();
    apply(
        external,
        true,
        IntegerDataType.dataType,
        IntegerDataType.dataType,
        IntegerDataType.dataType,
        "__stdcall");
    external.setComment("preserved external owner");
    middle.setThunkedFunction(external);
    chained.setThunkedFunction(middle);

    Function methodOwner = function("ClassOwner");
    methodOwner.setParentNamespace(
        currentProgram
            .getSymbolTable()
            .createClass(null, "DormantTarget", SourceType.USER_DEFINED));
    apply(
        methodOwner,
        false,
        IntegerDataType.dataType,
        IntegerDataType.dataType,
        IntegerDataType.dataType,
        "__thiscall");
    Function method = function("ClassSource");
    method.setParentNamespace(
        currentProgram
            .getSymbolTable()
            .createClass(null, "DormantWrapper", SourceType.USER_DEFINED));
    DataType classValue = structure("ClassValue", 4);
    apply(method, false, classValue, classValue, IntegerDataType.dataType, "__thiscall");
    method.setThunkedFunction(methodOwner);
  }

  private JsonObject variable(Program program, String kind, Variable variable) {
    var dtm = program.getDataTypeManager();
    JsonObject row = new JsonObject();
    row.addProperty("kind", kind);
    row.addProperty(
        "symbol_id", variable.getSymbol() == null ? null : variable.getSymbol().getID());
    row.addProperty(
        "symbol_parent_id",
        variable.getSymbol() == null ? null : variable.getSymbol().getParentNamespace().getID());
    row.addProperty("function_id", variable.getFunction().getID());
    row.addProperty("name", variable.getName());
    row.addProperty("type", variable.getDataType().getPathName());
    row.addProperty("type_id", dtm.getID(variable.getDataType()));
    row.addProperty("length", variable.getDataType().getLength());
    if (variable instanceof Parameter parameter) {
      row.addProperty("formal_type", parameter.getFormalDataType().getPathName());
      row.addProperty("formal_type_id", dtm.getID(parameter.getFormalDataType()));
      row.addProperty("formal_length", parameter.getFormalDataType().getLength());
      row.addProperty("auto", parameter.isAutoParameter());
    }
    row.addProperty("storage", variable.getVariableStorage().toString());
    row.addProperty("storage_length", variable.getVariableStorage().size());
    row.addProperty("valid", variable.isValid());
    row.addProperty("comment", variable.getComment());
    row.addProperty("source", variable.getSource().name());
    return row;
  }

  private JsonObject abi(Program program, Function function) {
    JsonObject row = new JsonObject();
    row.addProperty("custom", function.hasCustomVariableStorage());
    row.addProperty("convention", function.getCallingConventionName());
    row.addProperty("source", function.getSignatureSource().name());
    row.addProperty("variadic", function.hasVarArgs());
    JsonArray variables = new JsonArray();
    variables.add(variable(program, "return", function.getReturn()));
    for (Parameter parameter : function.getParameters())
      variables.add(variable(program, "parameter", parameter));
    for (Variable local : function.getLocalVariables())
      variables.add(variable(program, "local", local));
    row.add("variables", variables);
    return row;
  }

  private TreeMap<String, Function> functions(Program program) throws Exception {
    TreeMap<String, Function> functions = new TreeMap<>();
    var symbols = program.getSymbolTable().getSymbols(null, SymbolType.FUNCTION, true);
    while (symbols.hasNext()) {
      monitor.checkCancelled();
      Function function = program.getFunctionManager().getFunction(symbols.next().getID());
      functions.put(function.getName(), function);
    }
    return functions;
  }

  private JsonObject live() throws Exception {
    JsonObject result = new JsonObject();
    for (var item : functions(currentProgram).entrySet()) {
      Function function = item.getValue();
      JsonObject row = new JsonObject();
      row.addProperty("id", function.getID());
      row.addProperty("symbol_id", function.getSymbol().getID());
      row.addProperty("parent_id", function.getParentNamespace().getID());
      row.addProperty("namespace", function.getParentNamespace().getName(true));
      row.addProperty("class_namespace", function.getParentNamespace() instanceof GhidraClass);
      row.addProperty("entry", function.getEntryPoint().toString());
      row.addProperty("external", function.isExternal());
      row.addProperty("comment", function.getComment());
      row.addProperty("repeatable_comment", function.getRepeatableComment());
      row.addProperty("thunk", function.isThunk());
      Function direct = function.getThunkedFunction(false),
          last = function.getThunkedFunction(true);
      row.addProperty("direct_id", direct == null ? null : direct.getID());
      row.addProperty("final_id", last == null ? null : last.getID());
      row.add("visible", abi(currentProgram, function));
      result.add(item.getKey(), row);
    }
    return result;
  }

  private JsonObject savedOwn() throws Exception {
    Object reader = new Object();
    Program copy =
        (Program)
            currentProgram
                .getDomainFile()
                .getReadOnlyDomainObject(reader, DomainFile.DEFAULT_VERSION, TaskMonitor.DUMMY);
    try {
      if (copy == currentProgram || copy.getCurrentTransactionInfo() != null)
        throw new IllegalStateException(
            "Own-view probe requires an independent transaction-free saved Program");
      JsonObject result = new JsonObject();
      int transaction = copy.startTransaction("Inspect saved dormant own ABIs");
      try {
        var functions = functions(copy);
        Map<String, Long> ids = new TreeMap<>();
        for (var item : functions.entrySet()) {
          ids.put(item.getKey(), item.getValue().getID());
          if (item.getValue().isThunk()) item.getValue().setThunkedFunction(null);
        }
        for (var item : ids.entrySet())
          result.add(
              item.getKey(), abi(copy, copy.getFunctionManager().getFunction(item.getValue())));
      } finally {
        copy.endTransaction(transaction, false);
      }
      if (copy.getCurrentTransactionInfo() != null)
        throw new IllegalStateException("Own-view probe leaked its transaction");
      return result;
    } finally {
      copy.release(reader);
    }
  }

  public void run() throws Exception {
    if (getScriptArgs()[0].equals("create")) {
      create();
      return;
    }
    JsonObject state = new JsonObject();
    state.add("live", live());
    state.add("own", savedOwn());
    println(state.toString());
  }
}
