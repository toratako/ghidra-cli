
import ghidra.app.script.GhidraScript;
import ghidra.docking.settings.FormatSettingsDefinition;
public class CheckResizeConflictRollback extends GhidraScript {
    public void run() throws Exception {
        var listing = currentProgram.getListing();
        for (int address : new int[] { 0x1000, 0x2000, 0x3000, 0x4000 }) {
            var data = listing.getDefinedDataAt(toAddr(address));
            if (data == null || data.getLength() != 4 || data.getDataType().getLength() != 4)
                throw new IllegalStateException("Applied data changed after rollback at " + address);
        }
        var neighbor = listing.getDefinedDataAt(toAddr(0x2006));
        if (neighbor == null || neighbor.getLength() != 4)
            throw new IllegalStateException("Following defined data was lost");
        if (listing.getInstructionAt(toAddr(0x3006)) == null)
            throw new IllegalStateException("Following instruction was lost");
        var packed = listing.getDefinedDataAt(toAddr(0x5000));
        if (packed.getLength() != 5 || FormatSettingsDefinition.DEF.getChoice(packed.getComponent(1)) != FormatSettingsDefinition.BINARY)
            throw new IllegalStateException("Packed applied component settings changed");
        var array = listing.getDefinedDataAt(toAddr(0x6000));
        if (array.getLength() != 8 || FormatSettingsDefinition.DEF.getChoice(array.getComponent(1).getComponent(0)) != FormatSettingsDefinition.DECIMAL)
            throw new IllegalStateException("Array component settings changed");
    }
}
