
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
public class CheckBitRemovalCountFixture extends GhidraScript {
    public void run() throws Exception {
        var structure = (Structure) currentProgram.getDataTypeManager().getDataType("/RemovalCountBits");
        var fields = structure.getDefinedComponents();
        if (structure.getLength() != Integer.MAX_VALUE || structure.getNumComponents() != Integer.MAX_VALUE - 1
                || fields.length != 3 || fields[2].getOrdinal() != 2 || fields[2].getOffset() != 0
                || !"wide".equals(fields[2].getFieldName()) || !"keep".equals(fields[2].getComment())
                || ((BitFieldDataType) fields[2].getDataType()).getBitSize() != 25)
            throw new IllegalStateException("Removal overflow rejection changed the saved structure");
    }
}
