package ghidracli;

import com.google.gson.JsonObject;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.function.Consumer;

public final class BridgeRuntime {
    private BridgeRuntime() {}

    public static void run(ScriptAccess script, String portFilePath, String initialProgram,
            Consumer<String> output) throws Exception {
        ProgramSession session = new ProgramSession(script);
        CommandDispatcher commands = new CommandDispatcher(session);
        JobScheduler jobs = new JobScheduler(session, commands);
        BridgeServer server = null;
        String stage = "bridge.bind";
        String path = "127.0.0.1:0";
        boolean readyPublished = false;
        try {
            server = new BridgeServer(jobs::handleRequest, jobs::beginShutdown,
                jobs::isShutdownComplete, script::logError);
            if (initialProgram != null) {
                stage = "bridge.program_open";
                path = initialProgram;
                JsonObject args = new JsonObject();
                args.addProperty("program", initialProgram);
                JsonObject response = commands.execute("open_program", args);
                if (!"success".equals(response.get("status").getAsString())) {
                    throw new IllegalArgumentException(response.get("message").getAsString());
                }
            }
            jobs.start();
            stage = "bridge.port_write";
            path = portFilePath;
            Path portFile = Path.of(portFilePath);
            Files.createDirectories(portFile.getParent());
            Files.writeString(portFile, Integer.toString(server.port()));
            stage = "bridge.pid_write";
            path = portFilePath.replaceAll("\\.port$", ".pid");
            Files.writeString(Path.of(path), Long.toString(ProcessHandle.current().pid()));
            JsonObject ready = new JsonObject();
            ready.addProperty("status", "ready");
            ready.addProperty("port", server.port());
            output.accept("---GHIDRA_CLI_START---");
            output.accept(ready.toString());
            output.accept("---GHIDRA_CLI_END---");
            System.out.flush();
            readyPublished = true;
            server.start();
            // Requests commit and save on the calling GhidraScript thread.
            jobs.runProgramJobs();
        } catch (Exception error) {
            if (!readyPublished) {
                JsonObject detail = new JsonObject();
                detail.addProperty("stage", stage);
                detail.addProperty("path", path);
                detail.addProperty("cause", error.toString());
                output.accept("GHIDRA_CLI_STARTUP_ERROR " + JsonProtocol.errorResponse(
                    stage + " failed at " + path + ": " + error, detail));
                System.out.flush();
            }
            throw error;
        } finally {
            jobs.beginShutdown();
            if (server != null) server.close();
            session.closeProgram();
            // Rust removes discovery files after the JVM releases project locks.
        }
    }
}
