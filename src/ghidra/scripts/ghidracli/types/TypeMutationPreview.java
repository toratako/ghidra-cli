package ghidracli.types;

import com.google.gson.JsonObject;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.exception.CancelledException;
import ghidracli.session.ProgramSession;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;

/** Validate dormant own definitions without changing the real thunk graph. */
public final class TypeMutationPreview {
  private final ProgramSession session;

  public TypeMutationPreview(ProgramSession session) {
    this.session = session;
  }

  /** The operation must resolve its native objects afresh on every invocation. */
  public JsonObject execute(Callable<JsonObject> operation) throws Exception {
    if (session.program() == null) return operation.call();
    List<ThunkEdge> edges = captureEdges();
    if (!edges.isEmpty()) {
      JsonObject checked =
          session.preview(
              "Validate dormant function definitions",
              () -> {
                setEdges(edges, false);
                List<SavedVariable> variables = captureVariables(edges);
                setEdges(edges, true);
                // Native replacement treats active thunk returns differently.
                // Run the same relation graph that the real mutation will see.
                JsonObject result = call(operation);
                if (result.has("error")) return result;
                setEdges(edges, false);
                for (SavedVariable variable : variables) variable.verify(session);
                session.monitor().checkCancelled();
                return result;
              });
      if (checked.has("error")) return checked;
    }
    return call(operation);
  }

  private JsonObject call(Callable<JsonObject> operation) throws Exception {
    session.monitor().checkCancelled();
    JsonObject result = operation.call();
    session.monitor().checkCancelled();
    return result;
  }

  private List<ThunkEdge> captureEdges() throws CancelledException {
    List<ThunkEdge> edges = new ArrayList<>();
    // Function symbols include external and unmapped owners, unlike a scan
    // restricted to the program's address set.
    var symbols = session.program().getSymbolTable().getSymbols(null, SymbolType.FUNCTION, true);
    while (symbols.hasNext()) {
      session.monitor().checkCancelled();
      Function function =
          session.program().getFunctionManager().getFunction(symbols.next().getID());
      Function target = function.getThunkedFunction(false);
      if (target != null) edges.add(new ThunkEdge(function.getID(), target.getID()));
    }
    session.monitor().checkCancelled();
    return edges;
  }

  private void setEdges(List<ThunkEdge> edges, boolean restore) throws CancelledException {
    for (ThunkEdge edge : edges) {
      session.monitor().checkCancelled();
      Function function = session.program().getFunctionManager().getFunction(edge.functionId);
      Function target =
          restore ? session.program().getFunctionManager().getFunction(edge.targetId) : null;
      if (function == null || restore && target == null)
        throw new IllegalStateException("Saved thunk function is missing");
      function.setThunkedFunction(target);
      session.monitor().checkCancelled();
      Function actual = function.getThunkedFunction(false);
      if (restore ? actual == null || actual.getID() != edge.targetId : actual != null)
        throw new IllegalStateException("Ghidra did not retain the preview thunk relation");
    }
  }

  private List<SavedVariable> captureVariables(List<ThunkEdge> edges) throws CancelledException {
    List<SavedVariable> variables = new ArrayList<>();
    for (ThunkEdge edge : edges) {
      session.monitor().checkCancelled();
      Function function = session.program().getFunctionManager().getFunction(edge.functionId);
      captureVariable(variables, function, function.getReturn(), true);
      for (Variable variable : function.getAllVariables()) {
        session.monitor().checkCancelled();
        if (variable instanceof Parameter parameter && parameter.isAutoParameter()) continue;
        captureVariable(variables, function, variable, false);
      }
    }
    session.monitor().checkCancelled();
    return variables;
  }

  private void captureVariable(
      List<SavedVariable> variables, Function function, Variable variable, boolean result)
      throws CancelledException {
    session.monitor().checkCancelled();
    DataType declared = declaredType(variable);
    var manager = session.program().getDataTypeManager();
    // Native missing-type fallback may look valid. It has no saved type
    // identity to preserve, and must not block unrelated edits or repairs.
    if (variable.isValid() && (declared == DataType.DEFAULT || manager.contains(declared))) {
      variables.add(
          new SavedVariable(
              function.getID(),
              result ? -1 : variable.getSymbol().getID(),
              manager.getID(declared),
              declared.getPathName(),
              (result ? "return" : variable instanceof Parameter ? "parameter" : "local")
                  + " '"
                  + variable.getName()
                  + "' in function '"
                  + function.getName()
                  + "'"));
    }
  }

  private static DataType declaredType(Variable variable) {
    return variable instanceof Parameter parameter
        ? parameter.getFormalDataType()
        : variable.getDataType();
  }

  private static final class ThunkEdge {
    final long functionId;
    final long targetId;

    ThunkEdge(long functionId, long targetId) {
      this.functionId = functionId;
      this.targetId = targetId;
    }
  }

  private static final class SavedVariable {
    final long functionId;
    final long symbolId;
    final long typeId;
    final String typePath;
    final String location;

    SavedVariable(long functionId, long symbolId, long typeId, String typePath, String location) {
      this.functionId = functionId;
      this.symbolId = symbolId;
      this.typeId = typeId;
      this.typePath = typePath;
      this.location = location;
    }

    void verify(ProgramSession session) throws CancelledException {
      session.monitor().checkCancelled();
      Function function = session.program().getFunctionManager().getFunction(functionId);
      Variable current = null;
      if (function != null) {
        if (symbolId == -1) current = function.getReturn();
        else {
          var symbol = session.program().getSymbolTable().getSymbol(symbolId);
          if (symbol != null
              && symbol.getParentNamespace().getID() == functionId
              && symbol.getObject() instanceof Variable variable) current = variable;
        }
      }
      if (current == null)
        throw new IllegalArgumentException(
            "Unsafe type mutation: saved " + location + " is missing");
      var manager = session.program().getDataTypeManager();
      DataType expected = manager.getDataType(typeId);
      // A kind-changing import can delete the original native ID. Its
      // intentional replacement retains the original registered path.
      if (expected == null) expected = manager.getDataType(typePath);
      DataType declared = declaredType(current);
      if (expected == null
          || !(declared == DataType.DEFAULT || manager.contains(declared))
          || manager.getID(declared) != manager.getID(expected)) {
        throw new IllegalArgumentException(
            "Unsafe type mutation: saved " + location + " did not retain its declared type");
      }
      if (!current.isValid())
        throw new IllegalArgumentException(
            "Unsafe type mutation: saved " + location + " no longer has complete type storage");
      session.monitor().checkCancelled();
    }
  }
}
