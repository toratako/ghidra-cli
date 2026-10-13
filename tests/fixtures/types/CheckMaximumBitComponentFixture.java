
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
public class CheckMaximumBitComponentFixture extends GhidraScript {
    public void run() throws Exception {
        var structure = (Structure) currentProgram.getDataTypeManager().getDataType("/MaximumBits");
        var fields = structure.getDefinedComponents();
        if (structure.getLength() != Integer.MAX_VALUE || structure.getNumComponents() != Integer.MAX_VALUE
                || fields.length != 1 || fields[0].getOrdinal() != 0 || fields[0].getOffset() != 0
                || !"first".equals(fields[0].getFieldName())
                || ((BitFieldDataType) fields[0].getDataType()).getBitSize() != 3)
            throw new IllegalStateException("Overflow rejection changed the saved structure");
    }
}
