import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;

public class CheckSparseTypeGetFixture extends GhidraScript {
  public void run() throws Exception {
    var structure = (Structure) currentProgram.getDataTypeManager().getDataType("/HugeSparseGet");
    var fields = structure.getDefinedComponents();
    if (structure.getLength() != Integer.MAX_VALUE
        || structure.getNumComponents() != Integer.MAX_VALUE - 3
        || fields.length != 1
        || fields[0].getOffset() != Integer.MAX_VALUE - 4
        || fields[0].getLength() != 4
        || !"tail".equals(fields[0].getFieldName())
        || !"keep".equals(fields[0].getComment()))
      throw new IllegalStateException("Type inspection changed the saved sparse structure");
  }
}
