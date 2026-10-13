
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.Structure;
import ghidra.docking.settings.FormatSettingsDefinition;
public class CheckAnchorFormat extends GhidraScript {
    public void run() throws Exception {
        var holder = (Structure) currentProgram.getDataTypeManager().getDataType("/Holder");
        if (FormatSettingsDefinition.DEF.getChoice(holder.getComponent(0).getDefaultSettings())
                != FormatSettingsDefinition.DECIMAL)
            throw new IllegalStateException("Append discarded an existing field's format setting");
    }
}
