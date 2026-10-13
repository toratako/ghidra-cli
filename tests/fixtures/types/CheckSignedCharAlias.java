
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.Structure;
public class CheckSignedCharAlias extends GhidraScript {
    public void run() throws Exception {
        var dtm = currentProgram.getDataTypeManager();
        if (dtm.getDataOrganization().isSignedChar())
            throw new IllegalStateException("Fixture must use unsigned plain char");
        var holder = (Structure) dtm.getDataType("/Holder");
        var signed = (CharDataType) holder.getComponent(0).getDataType();
        var plain = (CharDataType) holder.getComponent(1).getDataType();
        if (!signed.isSigned() || plain.isSigned())
            throw new IllegalStateException("Explicit signed char lost its signedness");
    }
}
