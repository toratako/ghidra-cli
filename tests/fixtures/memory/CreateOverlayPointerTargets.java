
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.symbol.SourceType;
public class CreateOverlayPointerTargets extends GhidraScript {
    public void run() throws Exception {
        var memory = currentProgram.getMemory();
        var space = currentProgram.getAddressFactory().getDefaultAddressSpace();
        var base = space.getAddress(0x2000);
        memory.createInitializedBlock("base_code", base, 4, (byte) 0, monitor, false);
        currentProgram.getFunctionManager().createFunction("base_target", base,
            new AddressSet(base, base.add(3)), SourceType.USER_DEFINED);
        var overlay = memory.createInitializedBlock("overlay", space.getAddress(0x1000),
            0x1004, (byte) 0, monitor, true);
        var start = overlay.getStart();
        var thumbMode = currentProgram.getRegister("TMode");
        byte modeBit = (byte) (thumbMode == null ? 0 : 1);
        memory.setBytes(start, new byte[] {modeBit, 0x20, 0, 0,
            (byte) (0x30 | modeBit), (byte) 0xda, 9, 7});
        var target = start.add(0x1000);
        if (thumbMode != null) {
            currentProgram.getProgramContext().setValue(thumbMode, target,
                target.add(3), java.math.BigInteger.ONE);
            var oddOverlay = memory.createInitializedBlock("odd_overlay", base.add(1),
                4, (byte) 0, monitor, true);
            memory.setBytes(oddOverlay.getStart(), new byte[] {1, 0x20, 0, 0});
        }
        currentProgram.getFunctionManager().createFunction("overlay_target", target,
            new AddressSet(target, target.add(3)), SourceType.USER_DEFINED);
    }
}
