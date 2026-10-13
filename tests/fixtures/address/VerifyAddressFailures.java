
import ghidra.app.script.GhidraScript;
public class VerifyAddressFailures extends GhidraScript {
    public void run() {
        var address = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(0x1600);
        if (currentProgram.getListing().getDefinedDataAt(address) != null
                || currentProgram.getListing().getInstructionAt(address) != null) {
            throw new IllegalStateException("Rejected address changed listing");
        }
    }
}
