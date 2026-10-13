import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.DWordDataType;

public class PrepareDefineDataMemory extends GhidraScript {
  public void run() throws Exception {
    var memory = currentProgram.getMemory();
    memory.createInitializedBlock("first", toAddr(0x1000), 8, (byte) 0xc3, monitor, false);
    memory.createInitializedBlock("after_gap", toAddr(0x1010), 8, (byte) 0, monitor, false);
    memory.createInitializedBlock("last", toAddr(0xfffffff0L), 16, (byte) 0, monitor, false);
    disassemble(toAddr(0x1000));
    createData(toAddr(0x1004), DWordDataType.dataType);
    createData(toAddr(0xfffffffcL), DWordDataType.dataType);
  }
}
