
import ghidra.app.script.GhidraScript;
import ghidra.docking.settings.FormatSettingsDefinition;
import ghidra.program.model.data.*;
public class CheckTaggedImportReferences extends GhidraScript {
    public void run() throws Exception {
        var manager = currentProgram.getDataTypeManager();
        var record = (Structure) manager.getDataType("/Existing/Record");
        var payload = manager.getDataType("/Existing/Payload");
        var status = manager.getDataType("/Existing/Status");
        var address = toAddr(0x1000);
        if (getScriptArgs()[0].equals("setup")) {
            currentProgram.getMemory().createInitializedBlock("data", address, 64, (byte) 0, monitor, false);
            var applied = currentProgram.getListing().createData(address, record);
            FormatSettingsDefinition.DEF.setChoice(applied.getComponent(0), FormatSettingsDefinition.DECIMAL);
            return;
        }
        var pointer = (Pointer) ((TypeDef) manager.getDataType("/Draft/RecordPtr")).getDataType();
        var holder = (Structure) manager.getDataType("/Draft/Holder");
        if (pointer.getDataType() != record
                || ((TypeDef) manager.getDataType("/Draft/PayloadAlias")).getDataType() != payload
                || ((TypeDef) manager.getDataType("/Draft/StatusAlias")).getDataType() != status
                || holder.getComponent(0).getDataType() != record
                || holder.getComponent(1).getDataType() != payload
                || holder.getComponent(2).getDataType() != status)
            throw new IllegalStateException("Tagged references did not retain registered identities");
        for (String name : new String[] { "Record", "Payload", "Status" })
            if (manager.getDataType("/Draft/" + name) != null || manager.getDataType("/" + name) != null)
                throw new IllegalStateException("Tagged reference created a replacement definition: " + name);
        var applied = currentProgram.getListing().getDefinedDataAt(address);
        if (applied == null || applied.getDataType() != record || applied.getLength() != 8
                || FormatSettingsDefinition.DEF.getChoice(applied.getComponent(0)) != FormatSettingsDefinition.DECIMAL)
            throw new IllegalStateException("Tagged reference changed existing applied data");
    }
}
