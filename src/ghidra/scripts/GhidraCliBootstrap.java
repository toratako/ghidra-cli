// Short-lived project initialization and durable import; never serves requests.
// @category Bridge
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import ghidra.app.script.GhidraScript;
import ghidracli.ImportSupport;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

public class GhidraCliBootstrap extends GhidraScript {
    public void run() throws Exception {
        end(true);
        String[] paths = getScriptArgs();
        JsonObject args = JsonParser.parseString(Files.readString(Path.of(paths[0]))).getAsJsonObject();
        JsonObject result;
        try {
            if (args.has("create_project") && args.get("create_project").getAsBoolean()) {
                result = new JsonObject();
                result.addProperty("status", "success");
                result.addProperty("ghidra_settings", ghidra.framework.Application.getUserSettingsDirectory().toString());
                result.addProperty("ghidra_cache", ghidra.framework.Application.getUserCacheDirectory().toString());
            } else {
                boolean analyze = args.has("analyze") && args.get("analyze").getAsBoolean();
                result = ImportSupport.run(state.getProject(), args, this, monitor,
                    analyze ? program -> analyzeAll(program) : null);
            }
        } catch (Exception error) {
            result = ImportSupport.failure(error);
        }
        Files.writeString(Path.of(paths[1]), result.toString(), StandardCharsets.UTF_8);
    }
}
