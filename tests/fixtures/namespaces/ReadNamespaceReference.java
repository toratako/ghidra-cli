
import ghidra.app.script.GhidraScript;
public class ReadNamespaceReference extends GhidraScript {
    public void run() {
        var reference = currentProgram.getReferenceManager().getReference(toAddr(0x1000), toAddr(0x1010), 0);
        println(reference.getSymbolID() + ":" + reference.getFromAddress() + ":" + reference.getToAddress()
            + ":" + reference.getReferenceType() + ":" + reference.getSource() + ":" + reference.isPrimary());
    }
}
