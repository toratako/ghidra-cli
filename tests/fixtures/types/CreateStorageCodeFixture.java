
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.symbol.SourceType;
public class CreateStorageCodeFixture extends GhidraScript {
    public void run() throws Exception {
        var address = toAddr(0x1000);
        var block = currentProgram.getMemory().createInitializedBlock("code", address, 16, (byte)0, monitor, false);
        block.setExecute(true);
        // mov eax,0x11223344; mov edx,0x55667788; ret
        currentProgram.getMemory().setBytes(address, new byte[] {
            (byte)0xb8, 0x44, 0x33, 0x22, 0x11, (byte)0xba, (byte)0x88, 0x77, 0x66, 0x55, (byte)0xc3
        });
        disassemble(address);
        currentProgram.getFunctionManager().createFunction("entry", address,
            new AddressSet(address, address.add(10)), SourceType.USER_DEFINED);
    }
}
