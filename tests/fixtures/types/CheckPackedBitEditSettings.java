
import ghidra.app.script.GhidraScript;
import ghidra.docking.settings.FormatSettingsDefinition;
import ghidra.program.model.data.Structure;
public class CheckPackedBitEditSettings extends GhidraScript {
    public void run() throws Exception {
        var packed = (Structure) currentProgram.getDataTypeManager().getDataType("/PackedBits");
        if (FormatSettingsDefinition.DEF.getChoice(packed.getComponent(0).getDefaultSettings())
                != FormatSettingsDefinition.DECIMAL)
            throw new IllegalStateException("Lost packed bit-field settings");
    }
}
