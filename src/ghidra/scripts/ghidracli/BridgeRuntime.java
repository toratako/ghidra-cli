package ghidracli;

import com.google.gson.JsonObject;
import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.function.Consumer;

public final class BridgeRuntime {
    private BridgeRuntime() {}

    public static void run(ScriptAccess script, String portFilePath, Consumer<String> output) throws Exception {
        ProgramSession session = new ProgramSession(script);
        JobScheduler jobs = new JobScheduler(session, new CommandDispatcher(session));
        BridgeServer server = new BridgeServer(jobs::handleRequest, jobs::beginShutdown,
            jobs::isShutdownRequested, script::logError);
        try {
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
            // This must remain on the calling GhidraScript thread. Returning
            // allows the headless harness to finish its transaction and save.
            jobs.runProgramJobs();
        } finally {
            jobs.beginShutdown();
            server.close();
            // Rust removes discovery files after the JVM releases project locks.
        }
    }
}
