
import ghidra.app.script.GhidraScript;
import ghidra.docking.settings.FormatSettingsDefinition;
import ghidra.program.model.data.*;
public class CreateResizeConflicts extends GhidraScript {
    public void run() throws Exception {
        var dtm = currentProgram.getDataTypeManager();
        for (String name : new String[] { "Embedded", "MemoryEdge", "DataNeighbor", "InstructionNeighbor", "Overflow", "AppliedEmpty", "AppliedSettings", "ArraySettings" }) {
            var child = new StructureDataType(CategoryPath.ROOT, name, 4, dtm);
            if (name.equals("ArraySettings")) child.replaceAtOffset(0, WordDataType.dataType, 2, "value", null);
            var saved = dtm.addDataType(child, null);
            if (name.equals("Embedded")) {
                var parent = new StructureDataType(CategoryPath.ROOT, "ConstrainedHolder", 8, dtm);
                parent.replaceAtOffset(0, saved, 4, "child", null);
                parent.replaceAtOffset(4, DWordDataType.dataType, 4, "tail", "do not consume");
                dtm.addDataType(parent, null);
            } else if (name.equals("Overflow")) {
                dtm.addDataType(new ArrayDataType(saved, 536870911, 4), null);
            } else {
                int address = name.equals("MemoryEdge") ? 0x1000 : name.equals("DataNeighbor") ? 0x2000
                    : name.equals("InstructionNeighbor") ? 0x3000 : name.equals("AppliedSettings") ? 0x5000
                    : name.equals("ArraySettings") ? 0x6000 : 0x4000;
                currentProgram.getMemory().createInitializedBlock(name, toAddr(address), name.equals("MemoryEdge") ? 6 : 32, (byte) 0x90, monitor, false);
                var listing = currentProgram.getListing();
                if (name.equals("AppliedSettings")) {
                    var packed = new StructureDataType(CategoryPath.ROOT, "SettingsHolder", 0, dtm);
                    packed.setPackingEnabled(true);
                    packed.add(saved, "child", null);
                    packed.add(ByteDataType.dataType, "tag", null);
                    var data = listing.createData(toAddr(address), dtm.addDataType(packed, null));
                    FormatSettingsDefinition.DEF.setChoice(data.getComponent(1), FormatSettingsDefinition.BINARY);
                } else if (name.equals("ArraySettings")) {
                    var data = listing.createData(toAddr(address), new ArrayDataType(saved, 2, 4));
                    FormatSettingsDefinition.DEF.setChoice(data.getComponent(1).getComponent(0), FormatSettingsDefinition.DECIMAL);
                } else {
                    listing.createData(toAddr(address), saved);
                }
                if (name.equals("DataNeighbor"))
                    currentProgram.getListing().createData(toAddr(address + 6), Undefined4DataType.dataType);
                if (name.equals("InstructionNeighbor")) disassemble(toAddr(address + 6));
            }
        }
    }
}

