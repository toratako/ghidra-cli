import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSet;

/** Leave an unowned conditional entry that reaches another function's annotated tail. */
public class CreateSharedTailFixture extends GhidraScript {
    public void run() throws Exception {
        var body = new AddressSet(toAddr(0x1000), toAddr(0x1005));
        body.add(toAddr(0x1010), toAddr(0x1015));
        getFunctionAt(toAddr(0x1000)).setBody(body);
        currentProgram.getMemory().setBytes(toAddr(0x1008),
            new byte[] {0x75, 0x06, (byte) 0xc3});
        if (getInstructionAt(toAddr(0x1008)) != null) {
            throw new IllegalStateException("New entry must exercise automatic disassembly");
        }
    }
}
