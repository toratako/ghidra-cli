package ghidracli;

import com.google.gson.JsonObject;
import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.function.Consumer;

public final class BridgeRuntime {
    private BridgeRuntime() {}

    public static void run(ScriptAccess script, String portFilePath, String initialProgram,
            Consumer<String> output) throws Exception {
        ProgramSession session = new ProgramSession(script);
        CommandDispatcher commands = new CommandDispatcher(session);
        JobScheduler jobs = new JobScheduler(session, commands);
        BridgeServer server = new BridgeServer(jobs::handleRequest, jobs::beginShutdown,
            jobs::isShutdownRequested, script::logError);
        try {
            if (initialProgram != null) {
                JsonObject args = new JsonObject();
                args.addProperty("program", initialProgram);
                JsonObject response = commands.execute("open_program", args);
                if (!"success".equals(response.get("status").getAsString())) {
                    throw new IllegalArgumentException(response.get("message").getAsString());
                }
            }
            jobs.start(server::closeServerSocket);
            File portFile = new File(portFilePath);
            portFile.getParentFile().mkdirs();
            try (PrintWriter writer = new PrintWriter(new FileWriter(portFile))) {
                writer.println(server.port());
            }
            File pidFile = new File(portFilePath.replaceAll("\\.port$", ".pid"));
            try (PrintWriter writer = new PrintWriter(new FileWriter(pidFile))) {
                writer.println(ProcessHandle.current().pid());
            }
            JsonObject ready = new JsonObject();
            ready.addProperty("status", "ready");
            ready.addProperty("port", server.port());
            output.accept("---GHIDRA_CLI_START---");
            output.accept(ready.toString());
            output.accept("---GHIDRA_CLI_END---");
            System.out.flush();
            server.start();
            // Requests commit and save on the calling GhidraScript thread.
            jobs.runProgramJobs();
        } finally {
            jobs.beginShutdown();
            server.close();
            session.closeProgram();
            // Rust removes discovery files after the JVM releases project locks.
        }
    }
}
