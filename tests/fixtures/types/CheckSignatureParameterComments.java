
import ghidra.app.script.GhidraScript;
public class CheckSignatureParameterComments extends GhidraScript {
    public void run() throws Exception {
        var parameters = getFunctionAt(toAddr(0x1000)).getParameters();
        for (var parameter : parameters) {
            String expected = parameter.getName().equals("added") ? null : "retain " + parameter.getName();
            if (!java.util.Objects.equals(expected, parameter.getComment()))
                throw new IllegalStateException("Lost comment for " + parameter.getName()
                    + ": " + parameter.getComment());
        }
        if (!parameters[0].getDataType().getName().equals("char *")
                || !parameters[1].getName().equals("added") || !parameters[2].getName().equals("keep"))
            throw new IllegalStateException("Signature parameter update was not applied");
    }
}
