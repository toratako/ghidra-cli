
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.Enum;
public class CheckEnumMetadata extends GhidraScript {
    public void run() throws Exception {
        var type = (Enum) currentProgram.getDataTypeManager().getDataType("/Mode");
        if (!type.getDescription().equals("recovered mode") || type.getLength() != 8
                || !type.getComment("Keep").equals("alias remains")
                || !type.getComment("Negative").equals("signed member"))
            throw new IllegalStateException("Enum metadata changed during deletion");
    }
}
