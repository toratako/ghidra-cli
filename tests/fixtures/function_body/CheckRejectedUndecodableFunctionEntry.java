
import ghidra.app.script.GhidraScript;
public class CheckRejectedUndecodableFunctionEntry extends GhidraScript {
    public void run() throws Exception {
        var address = toAddr(0x3000);
        var symbol = currentProgram.getSymbolTable().getPrimarySymbol(address);
        if (getFunctionAt(address) != null || getInstructionAt(address) != null
                || currentProgram.getMemory().getByte(address) != 0x0f
                || symbol == null || !"saved_entry".equals(symbol.getName())) {
            throw new IllegalStateException("Failed function creation changed saved bytes or their label");
        }
    }
}
