import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.PascalString255DataType;

public class CreatePartialStringValues extends GhidraScript {
  public void run() throws Exception {
    var memory = currentProgram.getMemory();
    var pascal = toAddr(0x8000);
    memory.createInitializedBlock(
        "pascal_prefix",
        pascal,
        new java.io.ByteArrayInputStream(new byte[] {1, 'x'}),
        2,
        monitor,
        false);
    memory.createUninitializedBlock("pascal_unreadable_tail", pascal.add(2), 254, false);
    createData(pascal, PascalString255DataType.dataType);
    // The applied data unit stays two bytes long after changing its length prefix.
    memory.setByte(pascal, (byte) 0xff);

    var terminated = toAddr(0x9000);
    memory.createInitializedBlock(
        "terminated_value",
        terminated,
        new java.io.ByteArrayInputStream(new byte[] {'o', 'k', 0}),
        3,
        monitor,
        false);
    memory.createUninitializedBlock("unused_array_tail", terminated.add(3), 5, false);
    createData(terminated, new ArrayDataType(CharDataType.dataType, 8, 1));
  }
}
