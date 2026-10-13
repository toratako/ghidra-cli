import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;

public class CheckExtendedFloatingCallback extends GhidraScript {
  public void run() throws Exception {
    var callee = getFunctionAt(toAddr(0x1100));
    var returned = callee.getReturn().getFormalDataType();
    if (returned.getLength() != 10 || !returned.getPathName().equals("/Recovered/ExtendedFloat")) {
      throw new IllegalStateException("Bound function return type changed");
    }
    for (var parameter : callee.getParameters()) {
      if (!parameter.getName().equals("value")) continue;
      var type = parameter.getFormalDataType();
      if (type.getLength() != 10 || !type.getPathName().equals("/Recovered/ExtendedFloat")) {
        throw new IllegalStateException("Bound function parameter type changed");
      }
    }
    var caller = getFunctionAt(toAddr(0x1000));
    var space = HighFunction.findOverrideSpace(caller);
    for (var symbol : currentProgram.getSymbolTable().getSymbols(toAddr(0x1005))) {
      if (!space.equals(symbol.getParentNamespace()) || !symbol.getName().startsWith("prt_"))
        continue;
      var signature = (FunctionDefinition) HighFunctionDBUtil.readOverride(symbol).getDataType();
      var callback =
          (FunctionDefinition) ((Pointer) signature.getArguments()[0].getDataType()).getDataType();
      if (callback.getReturnType().getLength() != 10
          || !callback.getReturnType().getPathName().equals("/Recovered/ExtendedFloat")
          || !callback.getArguments()[0].getDataType().getName().equals("float")) {
        throw new IllegalStateException("Bound callback floating types changed");
      }
      return;
    }
    throw new IllegalStateException("Missing call signature override");
  }
}
