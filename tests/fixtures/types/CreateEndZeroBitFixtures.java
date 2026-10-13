
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
public class CreateEndZeroBitFixtures extends GhidraScript {
    public void run() throws Exception {
        var dtm = currentProgram.getDataTypeManager();
        for (boolean empty : new boolean[] { true, false }) {
            var structure = new StructureDataType(empty ? "EmptyZeroBits" : "EndZeroBits", 0, dtm);
            if (!empty) structure.add(DWordDataType.dataType, "word", "keep");
            structure.addBitField(UnsignedIntegerDataType.dataType, 0, null, "boundary");
            dtm.addDataType(structure, null);
        }
    }
}
