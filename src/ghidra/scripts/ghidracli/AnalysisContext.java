package ghidracli;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import java.util.UUID;

/** Provenance for a single read result, not a retained analysis snapshot. */
final class AnalysisContext {
    private AnalysisContext() {}

    static JsonObject create(ProgramSession session, Function function, String representation)
            throws CancelledException {
        session.monitor().checkCancelled();
        JsonObject result = new JsonObject();
        result.addProperty("representation", representation);
        result.addProperty("result_id", UUID.randomUUID().toString());
        result.addProperty("id_scope", "result");
        var locator = session.state().getProject().getProjectLocator();
        JsonObject project = new JsonObject();
        project.addProperty("location", locator.getLocation());
        project.addProperty("name", locator.getName());
        result.add("project", project);
        result.addProperty("program", session.programPath());
        result.addProperty("modification", Long.toString(session.program().getModificationNumber()));
        result.addProperty("function", function.getName());
        result.addProperty("address", AddressCodec.format(function.getEntryPoint()));
        result.add("body_ranges", ranges(function.getBody(), session.monitor()));
        return result;
    }

    static JsonArray ranges(AddressSetView addresses, TaskMonitor monitor) throws CancelledException {
        JsonArray result = new JsonArray();
        for (var range : addresses.getAddressRanges()) {
            monitor.checkCancelled();
            JsonObject row = new JsonObject();
            row.addProperty("start", AddressCodec.format(range.getMinAddress()));
            row.addProperty("end", AddressCodec.format(range.getMaxAddress()));
            result.add(row);
        }
        monitor.checkCancelled();
        return result;
    }
}
