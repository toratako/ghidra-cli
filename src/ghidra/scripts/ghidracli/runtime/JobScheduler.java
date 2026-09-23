package ghidracli.runtime;

import com.google.gson.JsonArray;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import ghidra.framework.model.Project;
import ghidra.util.task.TaskMonitor;
import ghidracli.session.ProgramSession;
import java.util.ArrayDeque;
import java.util.Iterator;
import java.util.UUID;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedDeque;

import static ghidracli.protocol.JsonProtocol.errorResponse;
import static ghidracli.protocol.JsonProtocol.errorResult;
import static ghidracli.protocol.JsonProtocol.successResponse;

final class JobScheduler {
    private static final int MAX_PROGRAM_QUEUE = 256;
    private static final int MAX_STATUS_JOBS = 25;
    private final Object lifecycleLock = new Object();
    // Queue membership, active ownership, and state transitions share one lock.
    private final ArrayDeque<ProgramJob> programQueue = new ArrayDeque<>();
    private final ConcurrentHashMap<String, JobRecord> jobs = new ConcurrentHashMap<>();
    private final ConcurrentLinkedDeque<String> completedJobIds = new ConcurrentLinkedDeque<>();
    private final JobResultStore results = new JobResultStore();
    private final long startTime = System.currentTimeMillis();
    private final ProgramSession session;
    private final CommandDispatcher commands;
    private volatile boolean acceptingJobs;
    private volatile boolean shutdownRequested;
    private volatile boolean shutdownComplete;
    private CompletableFuture<JsonObject> shutdownCompletion;
    private volatile JobRecord activeJob;

    // Published only by the program thread; control requests never dereference Ghidra state.
    private volatile String currentProgramNameSnapshot;
    private volatile String currentProgramPathSnapshot;
    private volatile String projectNameSnapshot;
    private volatile int programCountSnapshot;

    JobScheduler(ProgramSession session, CommandDispatcher commands) {
        this.session = session;
        this.commands = commands;
    }

    void start() {
        refreshBridgeSnapshot();
        acceptingJobs = true;
    }

    boolean isShutdownComplete() { return shutdownComplete; }

    private static class JobRecord {
        final String id;
        final String command;
        final long enqueuedAt;
        final JobTaskMonitor monitor = new JobTaskMonitor();

        volatile String state = "queued";
        volatile long startedAt;
        volatile long finishedAt;
        volatile String error;
        JobResultStore.Entry result;

        JobRecord(String id, String command) {
            this.id = id;
            this.command = command;
            this.enqueuedAt = System.currentTimeMillis();
        }
    }

    private static class ProgramJob {
        final JobRecord record;
        final JsonObject args;
        final String program;
        // History owns only the bounded encoded snapshot, never this future or request.
        final CompletableFuture<JsonObject> completion = new CompletableFuture<>();

        ProgramJob(JobRecord record, JsonObject args, String program) {
            this.record = record;
            this.args = args;
            this.program = program;
        }
    }

    void runProgramJobs() {
        boolean interrupted = false;
        try {
            while (true) {
                ProgramJob job;
                synchronized (lifecycleLock) {
                    while (programQueue.isEmpty() && !shutdownRequested) {
                        try {
                            lifecycleLock.wait();
                        } catch (InterruptedException e) {
                            interrupted = true;
                            beginShutdown();
                        }
                    }
                    job = programQueue.pollFirst();
                    if (job != null) {
                        activeJob = job.record;
                        job.record.state = "running";
                        job.record.startedAt = System.currentTimeMillis();
                    }
                }
                if (job != null) {
                    executeProgramJob(job);
                } else if (finishShutdown()) {
                    return;
                }
            }
        } finally {
            if (interrupted) Thread.currentThread().interrupt();
        }
    }

    private void executeProgramJob(ProgramJob job) {
        JobRecord record = job.record;
        TaskMonitor bridgeMonitor = session.monitor();
        session.setMonitor(record.monitor);

        JsonObject result;
        String responseStatus;
        String failure = null;
        try {
            result = commands.execute(record.command, job.args, job.program);
            result.addProperty("job_id", record.id);
            responseStatus = result.has("status") ? result.get("status").getAsString() : "error";
            if ("error".equals(responseStatus) && result.has("message")) {
                failure = result.get("message").getAsString();
            }
        } catch (Exception e) {
            failure = e.getMessage();
            responseStatus = "error";
            result = errorResponse(failure);
            result.addProperty("job_id", record.id);
        } finally {
            session.setMonitor(bridgeMonitor);
            refreshBridgeSnapshot();
        }

        // Bind batch continuation to this job's final selection, before any
        // later job can change it. Controls and unexecuted jobs have no receipt.
        result.addProperty("selected_program", session.programPath());
        byte[] snapshot = results.snapshot(result);
        synchronized (lifecycleLock) {
            boolean failed = "error".equals(responseStatus);
            record.state = record.monitor.isCancelled()
                ? (failed ? "cancelled" : "completed_after_cancel")
                : (failed ? "failed" : "complete");
            record.error = failure;
            record.finishedAt = System.currentTimeMillis();
            activeJob = null;
            retainCompletedJob(record, snapshot);
        }
        job.completion.complete(result);
    }

    void beginShutdown() {
        synchronized (lifecycleLock) {
            if (shutdownRequested) return;
            shutdownCompletion = new CompletableFuture<>();
            shutdownRequested = true;
            acceptingJobs = false;
            // Wake an idle script thread without consuming bounded queue capacity.
            // The script thread exits only after all accepted jobs have drained.
            lifecycleLock.notifyAll();
        }
    }

    /** Runs on the program thread after every accepted job has completed. */
    private boolean finishShutdown() {
        JsonObject response;
        boolean saved = false;
        try {
            session.closeProgram();
            response = new JsonObject();
            response.addProperty("status", "shutdown");
            saved = true;
        } catch (Exception error) {
            JsonObject detail = new JsonObject();
            detail.addProperty("stage", "bridge.shutdown_save");
            detail.addProperty("save_failed", true);
            detail.addProperty("saved", false);
            detail.addProperty("program", session.programPath());
            response = errorResponse("Shutdown save failed: " + error.getMessage()
                + ". Bridge left running; resolve the cause and retry program save before stopping.", detail);
        }
        refreshBridgeSnapshot();
        CompletableFuture<JsonObject> completion;
        synchronized (lifecycleLock) {
            completion = shutdownCompletion;
            shutdownComplete = saved;
            if (!saved) {
                shutdownRequested = false;
                acceptingJobs = true;
            }
        }
        completion.complete(response);
        return saved;
    }

    BridgeReply handleRequest(String line) {
        try {
            JsonObject req = JsonParser.parseString(line).getAsJsonObject();
            String command = req.has("command") ? req.get("command").getAsString() : null;
            JsonObject args = req.has("args") && !req.get("args").isJsonNull()
                ? req.getAsJsonObject("args") : new JsonObject();

            if (command == null || command.isEmpty()) {
                return BridgeReply.immediate(errorResponse("Command required"));
            }
            String program = requestedProgram(req);
            if (program != null && (isControlCommand(command)
                    || "shutdown_wait".equals(command) || "job_result".equals(command))) {
                return BridgeReply.immediate(errorResponse("Control requests cannot select a program"));
            }

            // Wait outside the bounded program queue, without occupying a
            // connection thread. Controls remain available throughout draining.
            if ("shutdown_wait".equals(command)) {
                synchronized (lifecycleLock) {
                    beginShutdown();
                    return BridgeReply.pending(shutdownCompletion);
                }
            }

            if ("job_result".equals(command)) {
                String id = jobId(args);
                // Lookup/decoding and socket writes use the bounded response pool.
                return BridgeReply.deferred(() -> handleJobResult(id));
            }

            if (isControlCommand(command)) {
                synchronized (lifecycleLock) {
                    results.expire(System.currentTimeMillis());
                    return BridgeReply.immediate(handleControlCommand(command, args));
                }
            }

            JobRecord record = new JobRecord(jobId(req), command);
            ProgramJob job = new ProgramJob(record, args.deepCopy(), program);

            synchronized (lifecycleLock) {
                if (!acceptingJobs) {
                    return BridgeReply.immediate(errorResponse("Bridge is draining and is not accepting new program jobs"));
                }
                if (jobs.containsKey(record.id)) {
                    return BridgeReply.immediate(errorResponse("Job ID already exists; retrieve its result instead of resending the operation"));
                }
                if (programQueue.size() >= MAX_PROGRAM_QUEUE) {
                    return BridgeReply.immediate(errorResponse("Bridge program queue is full; retry shortly"));
                }
                jobs.put(record.id, record);
                programQueue.addLast(job);
                lifecycleLock.notifyAll();
            }
            return BridgeReply.pending(job.completion);
        } catch (Exception e) {
            return BridgeReply.immediate(
                errorResponse(e.getMessage()));
        }
    }

    private static String requestedProgram(JsonObject request) {
        if (!request.has("program")) return null;
        var value = request.get("program");
        if (!value.isJsonPrimitive() || !value.getAsJsonPrimitive().isString()
                || value.getAsString().isEmpty()) {
            throw new IllegalArgumentException("program must be a nonempty string");
        }
        return value.getAsString();
    }

    private static String jobId(JsonObject object) {
        if (!object.has("job_id") || object.get("job_id").isJsonNull()
                || !object.get("job_id").isJsonPrimitive()
                || !object.getAsJsonPrimitive("job_id").isString()) {
            throw new IllegalArgumentException("job_id must be a UUID");
        }
        String value = object.get("job_id").getAsString();
        String canonical = UUID.fromString(value).toString();
        if (!canonical.equalsIgnoreCase(value)) {
            throw new IllegalArgumentException("job_id must be a UUID");
        }
        return canonical;
    }

    private JsonObject handleJobResult(String id) {
        JsonObject result;
        byte[] body;
        synchronized (lifecycleLock) {
            results.expire(System.currentTimeMillis());
            JobRecord record = jobs.get(id);
            if (record == null) {
                JsonObject detail = new JsonObject();
                detail.addProperty("job_id", id);
                detail.addProperty("result_state", "unknown");
                return errorResponse("Job was not found; this does not establish that the operation was not executed", detail);
            }
            result = jobToJson(record, queuePosition(id));
            if (record.result == null || record.result.body == null) {
                JsonObject detail = new JsonObject();
                detail.addProperty("job_id", id);
                detail.addProperty("result_state", record.result == null ? "pending" : record.result.state);
                detail.add("job", result);
                return errorResponse(record.result == null
                    ? "Job has not finished; retrieve its result again later"
                    : "Job result is unavailable (" + record.result.state + "); inspect the job and program state before repeating the operation", detail);
            }
            body = record.result.body;
        }
        // The byte array is immutable; eviction may drop the cache reference while we read it.
        result.add("response", JsonParser.parseString(new String(body, StandardCharsets.UTF_8)));
        return successResponse(result);
    }

    private boolean isControlCommand(String command) {
        switch (command) {
            case "ping":
            case "status":
            case "bridge_info":
            case "job_status":
            case "job_cancel":
                return true;
            default:
                return false;
        }
    }

    private JsonObject handleControlCommand(String command, JsonObject args) {
        switch (command) {
            case "ping":
                return successResponse(handlePing());
            case "status":
                return successResponse(handleStatus());
            case "bridge_info":
                return successResponse(handleBridgeInfo());
            case "job_status":
                return successResponse(handleJobStatus(args));
            case "job_cancel": {
                JsonObject result = handleJobCancel(args);
                if (result.has("error")) {
                    return errorResponse(result.get("error").getAsString());
                }
                return successResponse(result);
            }
            default:
                return errorResponse("Unknown control command: " + command);
        }
    }

    private JsonObject handlePing() {
        JsonObject result = new JsonObject();
        result.addProperty("message", "pong");
        result.addProperty("bridge_state", acceptingJobs ? "running" : "draining");
        result.addProperty("queue_depth", programQueue.size());
        JobRecord active = activeJob;
        if (active != null) {
            result.addProperty("active_job_id", active.id);
            result.addProperty("active_command", active.command);
        }
        return result;
    }

    private JsonObject handleBridgeInfo() {
        JsonObject result = new JsonObject();
        String programName = currentProgramNameSnapshot;
        result.addProperty("protocol_version", 4);
        result.addProperty("current_program_path", currentProgramPathSnapshot);
        result.addProperty("has_current_program", programName != null);
        result.addProperty("auto_save", true);
        result.addProperty("atomic_edits", true);
        result.addProperty("explicit_addresses", true);
        result.addProperty("named_import", true);
        result.addProperty("durable_shutdown", true);
        if (programName != null) {
            result.addProperty("current_program", programName);
        }
        result.addProperty("uptime_ms", System.currentTimeMillis() - startTime);
        if (projectNameSnapshot != null) {
            result.addProperty("project_name", projectNameSnapshot);
        }
        result.addProperty("program_count", programCountSnapshot);
        addQueueSummary(result, false);
        return result;
    }

    private JsonObject handleStatus() {
        JsonObject result = new JsonObject();
        result.addProperty("protocol_version", 4);
        result.addProperty("uptime_ms", System.currentTimeMillis() - startTime);
        addQueueSummary(result, true);
        return result;
    }

    private JsonObject handleJobStatus(JsonObject args) {
        if (args != null && args.has("job_id") && !args.get("job_id").isJsonNull()) {
            String id = jobId(args);
            JobRecord record = jobs.get(id);
            if (record == null) {
                JsonObject result = new JsonObject();
                result.addProperty("found", false);
                result.addProperty("job_id", id);
                return result;
            }
            JsonObject result = new JsonObject();
            result.addProperty("found", true);
            result.add("job", jobToJson(record, queuePosition(id)));
            return result;
        }
        return handleStatus();
    }

    private JsonObject handleJobCancel(JsonObject args) {
        JobRecord target;
        if (args != null && args.has("job_id") && !args.get("job_id").isJsonNull()) {
            target = jobs.get(jobId(args));
        } else {
            target = activeJob;
        }

        if (target == null) {
            return errorResult("No matching active or queued job");
        }

        JobRecord active = activeJob;
        if (active != null && active.id.equals(target.id)) {
            target.state = "cancel_requested";
            target.monitor.cancel();
            JsonObject result = new JsonObject();
            result.addProperty("job_id", target.id);
            result.addProperty("state", target.state);
            result.addProperty("message", "Cancellation requested; completion is cooperative");
            return result;
        }

        ProgramJob queued = findQueuedJob(target.id);
        if (queued != null && programQueue.remove(queued)) {
            target.monitor.cancel();
            target.state = "cancelled";
            target.finishedAt = System.currentTimeMillis();
            target.error = "Cancelled before execution";
            JsonObject response = errorResponse(target.error);
            response.addProperty("job_id", target.id);
            retainCompletedJob(target, results.snapshot(response));
            queued.completion.complete(response);

            JsonObject result = new JsonObject();
            result.addProperty("job_id", target.id);
            result.addProperty("state", target.state);
            result.addProperty("message", target.error);
            return result;
        }

        JsonObject result = new JsonObject();
        result.addProperty("job_id", target.id);
        result.addProperty("state", target.state);
        result.addProperty("message", "Job is no longer cancellable");
        return result;
    }

    private ProgramJob findQueuedJob(String id) {
        for (ProgramJob job : programQueue) {
            if (job.record.id.equals(id)) {
                return job;
            }
        }
        return null;
    }

    private int queuePosition(String id) {
        int position = 0;
        for (ProgramJob job : programQueue) {
            if (job.record.id.equals(id)) {
                return position;
            }
            position++;
        }
        return -1;
    }

    private void addQueueSummary(JsonObject result, boolean includeJobs) {
        result.addProperty("bridge_state", acceptingJobs ? "running" : "draining");
        result.addProperty("accepting_jobs", acceptingJobs);
        result.addProperty("shutdown_requested", shutdownRequested);
        result.addProperty("queue_depth", programQueue.size());

        JobRecord active = activeJob;
        if (active == null) {
            result.add("active_job", JsonNull.INSTANCE);
        } else {
            result.add("active_job", jobToJson(active, -1));
        }

        if (!includeJobs) return;

        JsonArray queued = new JsonArray();
        int position = 0;
        for (ProgramJob job : programQueue) {
            if (queued.size() >= MAX_STATUS_JOBS) break;
            queued.add(jobToJson(job.record, position++));
        }
        result.add("queued_jobs", queued);

        JsonArray recent = new JsonArray();
        Iterator<String> ids = completedJobIds.descendingIterator();
        while (ids.hasNext() && recent.size() < MAX_STATUS_JOBS) {
            JobRecord record = jobs.get(ids.next());
            if (record != null) {
                recent.add(jobToJson(record, -1));
            }
        }
        result.add("recent_jobs", recent);
    }

    private JsonObject jobToJson(JobRecord record, int queuePosition) {
        JsonObject result = new JsonObject();
        result.addProperty("id", record.id);
        result.addProperty("command", record.command);
        result.addProperty("state", record.state);
        JsonObject availability = new JsonObject();
        availability.addProperty("state", "pending");
        result.add("result", record.result == null ? availability : record.result.status());
        result.addProperty("enqueued_at_ms", record.enqueuedAt);
        if (record.startedAt > 0) result.addProperty("started_at_ms", record.startedAt);
        if (record.finishedAt > 0) result.addProperty("finished_at_ms", record.finishedAt);
        long end = record.finishedAt > 0 ? record.finishedAt : System.currentTimeMillis();
        long start = record.startedAt > 0 ? record.startedAt : record.enqueuedAt;
        result.addProperty("elapsed_ms", Math.max(0, end - start));
        if (queuePosition >= 0) result.addProperty("queue_position", queuePosition);
        result.addProperty("cancel_requested", record.monitor.isCancelled());
        result.addProperty("cancel_enabled", record.monitor.isCancelEnabled());
        result.addProperty("progress", record.monitor.getProgress());
        result.addProperty("maximum", record.monitor.getMaximum());
        result.addProperty("indeterminate", record.monitor.isIndeterminate());
        String message = record.monitor.getMessage();
        if (message != null && !message.isEmpty()) result.addProperty("progress_message", message);
        if (record.error != null) result.addProperty("error", record.error);
        return result;
    }

    private void retainCompletedJob(JobRecord record, byte[] snapshot) {
        record.result = results.retain(snapshot, record.finishedAt);
        completedJobIds.addLast(record.id);
        while (completedJobIds.size() > JobResultStore.MAX_JOBS) {
            String expired = completedJobIds.pollFirst();
            JobRecord removed = expired == null ? null : jobs.remove(expired);
            if (removed != null) results.forget(removed.result);
        }
    }

    private void refreshBridgeSnapshot() {
        currentProgramNameSnapshot = session.programName();
        currentProgramPathSnapshot = session.programPath();

        Project project = session.state() == null ? null : session.state().getProject();
        projectNameSnapshot = project == null ? null : project.getName();
        programCountSnapshot = 0;
        if (project != null) {
            try {
                programCountSnapshot = session.programFiles().size();
            } catch (Exception ignored) {
                programCountSnapshot = 0;
            }
        }
    }
}
