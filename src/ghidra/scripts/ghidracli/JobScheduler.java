package ghidracli;

import com.google.gson.JsonArray;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectData;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import java.util.Iterator;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.atomic.AtomicLong;
import static ghidracli.JsonProtocol.errorResponse;
import static ghidracli.JsonProtocol.errorResult;
import static ghidracli.JsonProtocol.successResponse;

final class JobScheduler {
    private static final int MAX_PROGRAM_QUEUE = 256;
    private static final int MAX_RETAINED_JOBS = 100;
    private static final int MAX_STATUS_JOBS = 25;
    private final Object lifecycleLock = new Object();
    private final BlockingQueue<ProgramJob> programQueue = new ArrayBlockingQueue<>(MAX_PROGRAM_QUEUE);
    private final ConcurrentHashMap<Long, JobRecord> jobs = new ConcurrentHashMap<>();
    private final ConcurrentLinkedDeque<Long> completedJobIds = new ConcurrentLinkedDeque<>();
    private final AtomicLong nextJobId = new AtomicLong(1);
    private final long startTime = System.currentTimeMillis();
    private final Thread programThread = Thread.currentThread();
    private final ProgramSession session;
    private final CommandDispatcher commands;
    private Runnable closeListener;
    private volatile boolean acceptingJobs;
    private volatile boolean shutdownRequested;
    private volatile JobRecord activeJob;

    // Published only by the program thread; control requests never dereference Ghidra state.
    private volatile String currentProgramNameSnapshot;
    private volatile String projectNameSnapshot;
    private volatile int programCountSnapshot;

    JobScheduler(ProgramSession session, CommandDispatcher commands) {
        this.session = session;
        this.commands = commands;
    }

    void start(Runnable closeListener) {
        this.closeListener = closeListener;
        refreshBridgeSnapshot();
        acceptingJobs = true;
    }

    boolean isShutdownRequested() { return shutdownRequested; }

    private static class JobRecord {
        final long id;
        final String command;
        final long enqueuedAt;
        final JobTaskMonitor monitor = new JobTaskMonitor();
        final CompletableFuture<JsonObject> completion = new CompletableFuture<>();

        volatile String state = "queued";
        volatile long startedAt;
        volatile long finishedAt;
        volatile String error;

        JobRecord(long id, String command) {
            this.id = id;
            this.command = command;
            this.enqueuedAt = System.currentTimeMillis();
        }
    }

    private static class ProgramJob {
        final JobRecord record;
        final JsonObject args;
        final boolean poison;

        ProgramJob(JobRecord record, JsonObject args) {
            this(record, args, false);
        }

        private ProgramJob(JobRecord record, JsonObject args, boolean poison) {
            this.record = record;
            this.args = args;
            this.poison = poison;
        }

        static ProgramJob poison() {
            return new ProgramJob(null, null, true);
        }
    }

    void runProgramJobs() {
        while (true) {
            ProgramJob job;
            try {
                job = programQueue.take();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                beginShutdown();
                return;
            }

            if (job.poison) {
                return;
            }
            executeProgramJob(job);
        }
    }

    private void executeProgramJob(ProgramJob job) {
        JobRecord record = job.record;
        TaskMonitor bridgeMonitor = session.monitor();
        activeJob = record;
        record.state = "running";
        record.startedAt = System.currentTimeMillis();
        session.setMonitor(record.monitor);

        JsonObject result;
        try {
            result = commands.execute(record.command, job.args);
            result.addProperty("job_id", record.id);

            String responseStatus = result.has("status")
                ? result.get("status").getAsString()
                : "error";
            if (record.monitor.isCancelled()) {
                record.state = "error".equals(responseStatus)
                    ? "cancelled"
                    : "completed_after_cancel";
            } else {
                record.state = "error".equals(responseStatus) ? "failed" : "complete";
            }
            if ("error".equals(responseStatus) && result.has("message")) {
                record.error = result.get("message").getAsString();
            }
        } catch (Exception e) {
            record.state = record.monitor.isCancelled() ? "cancelled" : "failed";
            record.error = e.getMessage();
            result = errorResponse(e.getMessage());
            result.addProperty("job_id", record.id);
        } finally {
            session.setMonitor(bridgeMonitor);
            record.finishedAt = System.currentTimeMillis();
            activeJob = null;
            refreshBridgeSnapshot();
        }

        record.completion.complete(result);
        retainCompletedJob(record.id);
    }

    void beginShutdown() {
        Runnable listenerToClose;
        boolean enqueuePoison = false;
        synchronized (lifecycleLock) {
            if (shutdownRequested) {
                return;
            }
            shutdownRequested = true;
            acceptingJobs = false;
            listenerToClose = closeListener;
            if (Thread.currentThread() != programThread) {
                enqueuePoison = true;
            }
        }

        if (listenerToClose != null) listenerToClose.run();

        if (enqueuePoison) {
            // FIFO placement drains every job accepted before shutdown. Preserve
            // interruption but do not strand the GhidraScript thread without its
            // shutdown sentinel if the bounded queue is temporarily full.
            boolean interrupted = false;
            while (true) {
                try {
                    programQueue.put(ProgramJob.poison());
                    break;
                } catch (InterruptedException e) {
                    interrupted = true;
                }
            }
            if (interrupted) {
                Thread.currentThread().interrupt();
            }
        }
    }

    CompletableFuture<JsonObject> handleRequest(String line) {
        try {
            JsonObject req = JsonParser.parseString(line).getAsJsonObject();
            String command = req.has("command") ? req.get("command").getAsString() : null;
            JsonObject args = req.has("args") && !req.get("args").isJsonNull()
                ? req.getAsJsonObject("args") : new JsonObject();

            if (command == null || command.isEmpty()) {
                return CompletableFuture.completedFuture(
    /**
     * Error response carrying structured detail (e.g. a conflicting code
     * unit's type/range, or a containing function's name/entry/size) alongside
     * the message, so callers can act on it without a follow-up round trip.
     */
                    errorResponse("Command required"));
            }

            if (isControlCommand(command)) {
                return CompletableFuture.completedFuture(handleControlCommand(command, args));
            }

            JobRecord record = new JobRecord(nextJobId.getAndIncrement(), command);
            ProgramJob job = new ProgramJob(record, args.deepCopy());

            synchronized (lifecycleLock) {
                if (!acceptingJobs) {
                    return CompletableFuture.completedFuture(errorResponse("Bridge is draining and is not accepting new program jobs"));
                }
                jobs.put(record.id, record);
                if (!programQueue.offer(job)) {
                    jobs.remove(record.id);
                    return CompletableFuture.completedFuture(errorResponse("Bridge program queue is full; retry shortly"));
                }
            }
            return record.completion;
        } catch (Exception e) {
            return CompletableFuture.completedFuture(
                errorResponse(e.getMessage()));
        }
    }

    private boolean isControlCommand(String command) {
        switch (command) {
            case "ping":
            case "status":
            case "bridge_info":
            case "job_status":
            case "job_cancel":
            case "shutdown":
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
            case "shutdown": {
                beginShutdown();
                JsonObject response = new JsonObject();
                response.addProperty("status", "shutdown");
                response.addProperty("mode", "drain");
                return response;
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
        result.addProperty("protocol_version", 2);
        result.addProperty("has_current_program", programName != null);
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
        result.addProperty("protocol_version", 2);
        result.addProperty("uptime_ms", System.currentTimeMillis() - startTime);
        addQueueSummary(result, true);
        return result;
    }

    private JsonObject handleJobStatus(JsonObject args) {
        if (args != null && args.has("job_id") && !args.get("job_id").isJsonNull()) {
            long id = args.get("job_id").getAsLong();
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
            target = jobs.get(args.get("job_id").getAsLong());
        } else {
            target = activeJob;
        }

        if (target == null) {
            return errorResult("No matching active or queued job");
        }

        JobRecord active = activeJob;
        if (active != null && active.id == target.id) {
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
            target.completion.complete(response);
            retainCompletedJob(target.id);

            JsonObject result = new JsonObject();
            result.addProperty("job_id", target.id);
            result.addProperty("state", target.state);
            result.addProperty("message", target.error);
            return result;
        }

        // It may have moved from the queue to active between the checks above.
        active = activeJob;
        if (active != null && active.id == target.id) {
            target.state = "cancel_requested";
            target.monitor.cancel();
            JsonObject result = new JsonObject();
            result.addProperty("job_id", target.id);
            result.addProperty("state", target.state);
            result.addProperty("message", "Cancellation requested; completion is cooperative");
            return result;
        }

        JsonObject result = new JsonObject();
        result.addProperty("job_id", target.id);
        result.addProperty("state", target.state);
        result.addProperty("message", "Job is no longer cancellable");
        return result;
    }

    private ProgramJob findQueuedJob(long id) {
        for (ProgramJob job : programQueue) {
            if (!job.poison && job.record != null && job.record.id == id) {
                return job;
            }
        }
        return null;
    }

    private int queuePosition(long id) {
        int position = 0;
        for (ProgramJob job : programQueue) {
            if (job.poison) continue;
            if (job.record != null && job.record.id == id) {
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
        result.addProperty("queue_depth", queuedJobCount());

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
            if (job.poison || job.record == null) continue;
            if (queued.size() >= MAX_STATUS_JOBS) break;
            queued.add(jobToJson(job.record, position++));
        }
        result.add("queued_jobs", queued);

        JsonArray recent = new JsonArray();
        Iterator<Long> ids = completedJobIds.descendingIterator();
        while (ids.hasNext() && recent.size() < MAX_STATUS_JOBS) {
            JobRecord record = jobs.get(ids.next());
            if (record != null) {
                recent.add(jobToJson(record, -1));
            }
        }
        result.add("recent_jobs", recent);
    }

    private int queuedJobCount() {
        int count = 0;
        for (ProgramJob job : programQueue) {
            if (!job.poison) count++;
        }
        return count;
    }

    private JsonObject jobToJson(JobRecord record, int queuePosition) {
        JsonObject result = new JsonObject();
        result.addProperty("id", record.id);
        result.addProperty("command", record.command);
        result.addProperty("state", record.state);
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

    private void retainCompletedJob(long id) {
        completedJobIds.addLast(id);
        while (completedJobIds.size() > MAX_RETAINED_JOBS) {
            Long expired = completedJobIds.pollFirst();
            if (expired != null) jobs.remove(expired);
        }
    }

    private void refreshBridgeSnapshot() {
        Program program = session.program();
        currentProgramNameSnapshot = program == null ? null : program.getName();

        Project project = session.state() == null ? null : session.state().getProject();
        projectNameSnapshot = project == null ? null : project.getName();
        programCountSnapshot = 0;
        if (project != null) {
            try {
                ProjectData projectData = project.getProjectData();
                DomainFolder rootFolder = projectData.getRootFolder();
                programCountSnapshot = rootFolder.getFiles().length;
            } catch (Exception ignored) {
                programCountSnapshot = 0;
            }
        }
    }
}
