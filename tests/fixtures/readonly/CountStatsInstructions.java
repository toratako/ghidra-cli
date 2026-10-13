
import ghidra.app.script.GhidraScript;
public class CountStatsInstructions extends GhidraScript {
    public void run() throws Exception {
        long count = 0;
        var instructions = currentProgram.getListing().getInstructions(true);
        while (instructions.hasNext()) {
            monitor.checkCancelled();
            instructions.next();
            count++;
        }
        println(Long.toString(count));
    }
}
