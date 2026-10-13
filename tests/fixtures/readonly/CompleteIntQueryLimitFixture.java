
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.symbol.SourceType;
public class CompleteIntQueryLimitFixture extends GhidraScript {
    public void run() throws Exception {
        var space = currentProgram.getAddressFactory().getDefaultAddressSpace();
        for (int i = 0; i < 2; i++) {
            var address = space.getAddress(0x1000 + i * 0x10);
            currentProgram.getMemory().setByte(address, (byte) 0xc3);
            if (!new DisassembleCommand(address, new AddressSet(address), false).applyTo(currentProgram, monitor)) {
                throw new IllegalStateException("Could not disassemble fixture");
            }
            currentProgram.getSymbolTable().addExternalEntryPoint(address);
            currentProgram.getExternalManager().addExtFunction("test_library", "import" + i, null, SourceType.USER_DEFINED);
        }
        currentProgram.getFunctionManager().getFunctionAt(space.getAddress(0x1000)).addTag("second");
    }
}
