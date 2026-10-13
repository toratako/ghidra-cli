
import ghidra.app.script.GhidraScript;
import ghidra.docking.settings.FormatSettingsDefinition;
import ghidra.program.model.data.*;
public class CheckResizeFieldSettings extends GhidraScript {
    public void run() throws Exception {
        var tail = (Structure) currentProgram.getDataTypeManager().getDataType("/Tail");
        var settings = tail.getComponentAt(0).getDefaultSettings();
        if (FormatSettingsDefinition.DEF.getChoice(settings) != FormatSettingsDefinition.DECIMAL
                || EndianSettingsDefinition.DEF.getChoice(settings) != EndianSettingsDefinition.BIG)
            throw new IllegalStateException("Field settings were lost");
    }
}
