
import ghidra.app.script.GhidraScript;
public class CheckExplicitThisParameterComments extends GhidraScript {
    public void run() throws Exception {
        var function = getFunctionAt(toAddr(0x1100));
        if (!"saved explicit object".equals(function.getParameter(0).getComment())
                || !"saved count".equals(function.getParameter(1).getComment()))
            throw new IllegalStateException("Convention edit lost parameter comments");
    }
}
