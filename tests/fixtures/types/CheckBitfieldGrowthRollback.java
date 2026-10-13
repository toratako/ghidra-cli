import ghidra.app.script.GhidraScript;

public class CheckBitfieldGrowthRollback extends GhidraScript {
  public void run() throws Exception {
    var data = currentProgram.getListing().getDefinedDataAt(toAddr(0x1000));
    if (data == null || data.getLength() != 4 || data.getDataType().getLength() != 4)
      throw new IllegalStateException("Bitfield growth left incomplete applied data");
  }
}
