
import ghidra.app.script.GhidraScript;
import ghidra.docking.settings.FormatSettingsDefinition;
import ghidra.program.model.data.Structure;
public class CheckBitEditSettings extends GhidraScript {
    public void run() throws Exception {
        var bits = (Structure) currentProgram.getDataTypeManager().getDataType("/Bits");
        for (var field : bits.getDefinedComponents())
            if (field.getFieldName() != null && FormatSettingsDefinition.DEF.getChoice(field.getDefaultSettings())
                    != FormatSettingsDefinition.DECIMAL)
                throw new IllegalStateException("Lost setting: " + field.getFieldName());
    }
}
