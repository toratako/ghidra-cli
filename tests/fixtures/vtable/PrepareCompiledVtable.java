import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.symbol.SourceType;

/** Labels address points; preserves the compiler's bytes and loader relocations. */
public class PrepareCompiledVtable extends GhidraScript {
    private Address symbol(String name) {
        var symbols = currentProgram.getSymbolTable().getGlobalSymbols(name);
        if (symbols.size() != 1) throw new IllegalStateException("Expected one " + name);
        return symbols.get(0).getAddress();
    }

    public void run() throws Exception {
        if (getScriptArgs()[0].equals("msvc")) {
            createLabel(symbol("??_7Derived@@6BLeft@@@"), "derived_primary", true,
                SourceType.USER_DEFINED);
            createLabel(symbol("??_7Derived@@6BRight@@@"), "derived_secondary", true,
                SourceType.USER_DEFINED);
            functions(new String[] {"?left@Derived@@UEAAHXZ", "?right@Derived@@UEAAHXZ"});
            return;
        }
        int entrySize = Integer.parseInt(getScriptArgs()[0]);
        var table = symbol("_ZTV7Derived");
        createLabel(table.add(2 * entrySize), "derived_primary", true, SourceType.USER_DEFINED);
        createLabel(table.add(6 * entrySize), "derived_secondary", true, SourceType.USER_DEFINED);
        functions(new String[] {"_ZN7Derived4leftEv", "_ZN7Derived5rightEv", "_ZThn8_N7Derived5rightEv"});
    }

    private void functions(String[] names) throws Exception {
        for (String name : names) {
            var entry = symbol(name);
            if (currentProgram.getFunctionManager().getFunctionAt(entry) == null) {
                currentProgram.getFunctionManager().createFunction(name, entry,
                    new AddressSet(entry, entry.add(5)), SourceType.USER_DEFINED);
            }
        }
    }
}
