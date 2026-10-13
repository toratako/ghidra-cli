
import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
public class AddInteriorStringRefs extends GhidraScript {
    public void run() throws Exception {
        var space = currentProgram.getAddressFactory().getDefaultAddressSpace();
        currentProgram.getMemory().createInitializedBlock("references", space.getAddress(0x1000),
            0x100, (byte) 0, monitor, false);
        var refs = currentProgram.getReferenceManager();
        for (int encoding = 0; encoding < 2; encoding++) {
            var start = space.getAddress(0x2000 + encoding * 0x1000);
            var data = currentProgram.getListing().getDataAt(start);
            var from = space.getAddress(0x1000 + encoding * 0x10);
            var suffix = start.add(encoding == 0 ? 3 : 4);
            refs.addMemoryReference(from, start, RefType.DATA, SourceType.USER_DEFINED, 0);
            refs.addMemoryReference(from.add(1), suffix, RefType.DATA, SourceType.USER_DEFINED, 0);
            refs.addMemoryReference(from.add(1), suffix, RefType.DATA, SourceType.USER_DEFINED, 1);
            refs.addMemoryReference(from.add(2), data.getMaxAddress(),
                RefType.DATA, SourceType.USER_DEFINED, 0);
            refs.addMemoryReference(from.add(3), start.subtract(1),
                RefType.DATA, SourceType.USER_DEFINED, 0);
            refs.addMemoryReference(from.add(4), data.getMaxAddress().add(1),
                RefType.DATA, SourceType.USER_DEFINED, 0);
        }
    }
}
