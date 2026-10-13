
import ghidra.app.script.GhidraScript;
public class LocateNamedExternalFunction extends GhidraScript {
    public void run() throws Exception {
        currentProgram.getExternalManager().getUniqueExternalLocation("library", "outside_target")
            .setAddress(toAddr(0x5000));
    }
}
