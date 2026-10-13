
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.Structure;
public class CheckLargeBitOffsetFixture extends GhidraScript {
    public void run() throws Exception {
        var structure = (Structure) currentProgram.getDataTypeManager().getDataType("/HugeBits");
        var fields = structure.getDefinedComponents();
        if (structure.getLength() != 0x10000004 || fields.length != 1 || fields[0].getOffset() != 0x10000000
                || !"tail".equals(fields[0].getFieldName()) || !"keep".equals(fields[0].getComment()))
            throw new IllegalStateException("Large structure changed after rejected insertion");
    }
}
