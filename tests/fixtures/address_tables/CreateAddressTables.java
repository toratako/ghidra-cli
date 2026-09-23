import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;

public class CreateAddressTables extends GhidraScript {
    public void run() throws Exception {
        var space = currentProgram.getAddressFactory().getDefaultAddressSpace();
        var memory = currentProgram.getMemory();
        memory.createInitializedBlock("targets", space.getAddress(0x3000),
            0x100, (byte) 0, monitor, false);
        currentProgram.getSymbolTable().createLabel(space.getAddress(0x1000),
            "aligned_table", SourceType.USER_DEFINED);
        currentProgram.getSymbolTable().createLabel(space.getAddress(0x1040),
            "odd_targets", SourceType.USER_DEFINED);
        int width = currentProgram.getDefaultPointerSize();
        currentProgram.getReferenceManager().addMemoryReference(space.getAddress(0x3080),
            space.getAddress(0x1080 + width * 2), RefType.DATA, SourceType.USER_DEFINED, 0);
        // Search must tolerate existing data; the GUI detector does not require
        // undefined listing bytes and does not create definitions itself.
        createData(space.getAddress(0x1000), new ghidra.program.model.data.ArrayDataType(
            ghidra.program.model.data.ByteDataType.dataType, width * 3, 1));
        var overlay = memory.createInitializedBlock("table_overlay", space.getAddress(0x1000),
            0x80, (byte) 0xff, monitor, true).getStart();
        for (int i = 0; i < 3; i++) {
            if (width == 4) memory.setInt(overlay.add(i * width), 0x1040 + i * 0x10);
            else memory.setLong(overlay.add(i * width), 0x1040 + i * 0x10);
        }
    }
}
