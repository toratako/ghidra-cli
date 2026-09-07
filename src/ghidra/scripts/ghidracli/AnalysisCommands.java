package ghidracli;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import static ghidracli.JsonProtocol.errorResult;
import static ghidracli.JsonProtocol.getArgString;

final class AnalysisCommands {
    private final ProgramSession session;

    AnalysisCommands(ProgramSession session) {
        this.session = session;
    }

    JsonObject handleAnalyzerList(JsonObject args) {
        if (session.program() == null) return errorResult("No program loaded");

        try {
            ghidra.framework.options.Options analysisOptions = session.program().getOptions("Analyzers");
            JsonArray analyzers = new JsonArray();
            for (String optionName : analysisOptions.getOptionNames()) {
                if (optionName.contains(".")) continue;
                try {
                    boolean enabled = analysisOptions.getBoolean(optionName, false);
                    JsonObject entry = new JsonObject();
                    entry.addProperty("name", optionName);
                    entry.addProperty("enabled", enabled);
                    String description = analysisOptions.getDescription(optionName);
                    if (description != null && !description.isEmpty()) {
                        entry.addProperty("description", description);
                    }
                    analyzers.add(entry);
                } catch (Exception ignored) {
                    // Non-boolean analyzer options are not enable/disable switches.
                }
            }

            JsonObject result = new JsonObject();
            result.addProperty("count", analyzers.size());
            result.add("analyzers", analyzers);
            return result;
        } catch (Exception e) {
            return errorResult("Failed to list analyzers: " + e.getMessage());
        }
    }

    JsonObject handleAnalyzerSet(JsonObject args) {
        if (session.program() == null) return errorResult("No program loaded");

        String name = getArgString(args, "name");
        if (name == null || name.isEmpty()) return errorResult("analyzer name required");
        if (!args.has("enabled")) return errorResult("enabled (true/false) required");
        boolean enabled = args.get("enabled").getAsBoolean();

        try {
            ghidra.framework.options.Options analysisOptions = session.program().getOptions("Analyzers");
            if (!analysisOptions.getOptionNames().contains(name)) {
                return errorResult("Unknown analyzer: " + name);
            }

            ProgramTransaction transaction = session.transaction("Set analyzer");
            try {
                analysisOptions.setBoolean(name, enabled);
                transaction.end(true);
            } catch (Exception e) {
                transaction.end(false);
                throw e;
            }

            JsonObject result = new JsonObject();
            result.addProperty("status", "set");
            result.addProperty("name", name);
            result.addProperty("enabled", enabled);
            return result;
        } catch (Exception e) {
            return errorResult("Failed to set analyzer: " + e.getMessage());
        }
    }

    JsonObject handleAnalyzeRun(JsonObject args) {
        if (session.program() == null) return errorResult("No program loaded");

        try {
            ghidra.app.plugin.core.analysis.AutoAnalysisManager manager =
                ghidra.app.plugin.core.analysis.AutoAnalysisManager.getAnalysisManager(session.program());
            manager.reAnalyzeAll(null);
            // Use the same cross-version GhidraScript entry point as the normal
            // `analyze` command after marking all analyzers for re-analysis.
            session.analyzeAll(session.program());
            try {
                session.program().save("Re-analysis complete", session.monitor());
            } catch (Exception ignored) {
                // Best effort; clean bridge shutdown also persists changes.
            }

            JsonObject result = new JsonObject();
            result.addProperty("status", "analysis_complete");
            result.addProperty("program", session.program().getName());
            return result;
        } catch (Exception e) {
            return errorResult("Failed to run analysis: " + e.getMessage());
        }
    }
}
