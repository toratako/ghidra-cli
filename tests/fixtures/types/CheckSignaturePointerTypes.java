import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Pointer;

public class CheckSignaturePointerTypes extends GhidraScript {
  private void checkPointer(DataType type, int depth) {
    for (int i = 0; i < depth; i++) {
      if (!(type instanceof Pointer) || type.getLength() != currentProgram.getDefaultPointerSize())
        throw new IllegalStateException("Wrong pointer type or target width: " + type);
      type = ((Pointer) type).getDataType();
    }
    if (!type.equals(currentProgram.getDataTypeManager().getDataType("/Recovered/Entry")))
      throw new IllegalStateException("Wrong pointee: " + type);
  }

  public void run() throws Exception {
    var function = getFunctionAt(toAddr(0x1000));
    if (!"lookup".equals(function.getName()) || function.getParameterCount() != 2)
      throw new IllegalStateException("Function name or parameters changed");
    checkPointer(function.getReturnType(), Integer.parseInt(getScriptArgs()[0]));
    checkPointer(function.getParameter(0).getDataType(), 1);
    if (!"entry".equals(function.getParameter(0).getName())
        || !"index".equals(function.getParameter(1).getName())
        || !"int".equals(function.getParameter(1).getDataType().getName()))
      throw new IllegalStateException("Parameter name or type changed");
  }
}
