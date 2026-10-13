
import ghidra.app.script.GhidraScript;
import ghidra.docking.settings.FormatSettingsDefinition;
import ghidra.program.model.data.EndianSettingsDefinition;
import ghidra.program.model.data.Structure;
public class ApplyImportRollbackFixture extends GhidraScript {
    public void run() throws Exception {
        var structure = (Structure) currentProgram.getDataTypeManager().getDataType("/Existing");
        var component = structure.getComponent(0);
        component.setComment("saved field comment");
        FormatSettingsDefinition.DEF.setChoice(component.getDefaultSettings(), FormatSettingsDefinition.DECIMAL);
        EndianSettingsDefinition.DEF.setChoice(component.getDefaultSettings(), EndianSettingsDefinition.BIG);
        var address = toAddr(0x1000);
        currentProgram.getMemory().createInitializedBlock("data", address, 32, (byte) 0, monitor, false);
        var data = currentProgram.getListing().createData(address, structure);
        FormatSettingsDefinition.DEF.setChoice(data.getComponent(0), FormatSettingsDefinition.BINARY);
        EndianSettingsDefinition.DEF.setChoice(data.getComponent(0), EndianSettingsDefinition.LITTLE);
    }
}
