
import ghidra.app.script.GhidraScript;
import ghidra.docking.settings.FormatSettingsDefinition;
import ghidra.program.model.data.Structure;
public class SetBitEditSettings extends GhidraScript {
    public void run() throws Exception {
        var bits = (Structure) currentProgram.getDataTypeManager().getDataType("/Bits");
        for (var field : bits.getDefinedComponents())
            if (field.getFieldName() != null)
                FormatSettingsDefinition.DEF.setChoice(field.getDefaultSettings(), FormatSettingsDefinition.DECIMAL);
    }
}
