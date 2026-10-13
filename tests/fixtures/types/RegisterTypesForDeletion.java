import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.UnsignedIntegerDataType;

public class RegisterTypesForDeletion extends GhidraScript {
  public void run() throws Exception {
    var dtm = currentProgram.getDataTypeManager();
    for (int count : new int[] {4, 5})
      dtm.addDataType(new ArrayDataType(ByteDataType.dataType, count, -1, dtm), null);
    dtm.addDataType(new PointerDataType(ByteDataType.dataType, dtm), null);
    dtm.addDataType(new PointerDataType(CharDataType.dataType, dtm), null);
    dtm.addDataType(UnsignedIntegerDataType.dataType, null);
    dtm.addDataType(DWordDataType.dataType, null);
  }
}
