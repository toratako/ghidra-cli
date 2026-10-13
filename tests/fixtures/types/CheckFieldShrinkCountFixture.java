import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;

public class CheckFieldShrinkCountFixture extends GhidraScript {
  public void run() throws Exception {
    var structure =
        (Structure) currentProgram.getDataTypeManager().getDataType("/ShrinkCountFields");
    var fields = structure.getDefinedComponents();
    if (structure.getLength() != Integer.MAX_VALUE
        || structure.getNumComponents() != Integer.MAX_VALUE - 2
        || fields.length != 3
        || fields[2].getOrdinal() != 5
        || fields[2].getOffset() != 4
        || fields[2].getLength() != 4
        || !"word".equals(fields[2].getFieldName())
        || !"keep".equals(fields[2].getComment()))
      throw new IllegalStateException("Overflow rejection changed the saved structure");
  }
}
