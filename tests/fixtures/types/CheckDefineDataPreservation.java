import ghidra.app.script.GhidraScript;

public class CheckDefineDataPreservation extends GhidraScript {
  public void run() throws Exception {
    if (getInstructionAt(toAddr(0x1000)) == null)
      throw new IllegalStateException("Rejected apply removed instruction");
    for (long address : new long[] {0x1004, 0xfffffffcL}) {
      var data = getDataAt(toAddr(address));
      if (data == null
          || !data.isDefined()
          || data.getLength() != 4
          || !data.getDataType().getName().equals("dword"))
        throw new IllegalStateException("Rejected apply removed data");
    }
  }
}
