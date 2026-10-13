
import ghidra.app.script.GhidraScript;
import ghidra.docking.settings.FormatSettingsDefinition;
public class CheckFieldDeletionSettingsCases extends GhidraScript {
    public void run() throws Exception {
        var listing = currentProgram.getListing();
        for (int address : new int[] { 0x1000, 0x1100 }) {
            var data = listing.getDefinedDataAt(toAddr(address));
            if (FormatSettingsDefinition.DEF.getChoice(data.getComponent(1)) != FormatSettingsDefinition.BINARY)
                throw new IllegalStateException("Deletion lost a retained component's settings");
        }
        if (listing.getDefinedDataAt(toAddr(0x1200)).getLength() != 5
                || listing.getDefinedDataAt(toAddr(0x1300)).getLength() != 4)
            throw new IllegalStateException("Safe deletion failed to propagate complete data");
    }
}
