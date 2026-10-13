
import ghidra.app.script.GhidraScript;
import ghidra.docking.settings.FormatSettingsDefinition;
import ghidra.program.model.data.*;
public class CheckResizePropagation extends GhidraScript {
    public void run() throws Exception {
        int size = Integer.parseInt(getScriptArgs()[0]);
        var listing = currentProgram.getListing();
        int[] addresses = { 0x1000, 0x1080, 0x1100, 0x1180 };
        int[] lengths = { 40, size + 1, size * 4, size };
        for (int i = 0; i < addresses.length; i++) {
            var data = listing.getDefinedDataAt(toAddr(addresses[i]));
            if (data == null || data.getLength() != lengths[i] || data.getNumComponents() < 0)
                throw new IllegalStateException("Incomplete data at " + addresses[i]);
        }
        var nested = listing.getDefinedDataAt(toAddr(0x1100));
        if (nested.getComponent(1).getComponent(1).getMinAddress().getOffset() != 0x1100 + 3 * size)
            throw new IllegalStateException("Nested array stride did not propagate");
        var holder = (Structure) currentProgram.getDataTypeManager().getDataType("/Holder");
        if (FormatSettingsDefinition.DEF.getChoice(holder.getComponentAt(36).getDefaultSettings()) != FormatSettingsDefinition.BINARY)
            throw new IllegalStateException("Parent field settings were lost");
        if (FormatSettingsDefinition.DEF.getChoice(listing.getDefinedDataAt(toAddr(0x1180)).getComponent(0)) != FormatSettingsDefinition.DECIMAL)
            throw new IllegalStateException("Applied component settings were lost");
    }
}
