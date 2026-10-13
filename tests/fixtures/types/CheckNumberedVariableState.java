
import ghidra.app.script.GhidraScript;
public class CheckNumberedVariableState extends GhidraScript {
    public void run() throws Exception {
        var locals = getFunctionAt(toAddr(0x1000)).getLocalVariables();
        var names = java.util.Arrays.stream(locals).map(local -> local.getName())
            .collect(java.util.stream.Collectors.toSet());
        String name = getScriptArgs()[0];
        if (locals.length != 2 || !names.equals(java.util.Set.of(name, name + "$1")))
            throw new IllegalStateException("Unexpected numbered local names: " + names);
        for (var local : locals) {
            if (!getScriptArgs()[1].equals(local.getDataType().getName()))
                throw new IllegalStateException("Numbered local type was changed");
        }
    }
}
