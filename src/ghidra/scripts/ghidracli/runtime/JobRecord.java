package ghidracli.runtime;

import com.google.gson.JsonObject;

/** Per-job state and status projection; transitions run under the scheduler's lifecycle lock. */
final class JobRecord {
  final String id;
  final String command;
  final JobTaskMonitor monitor = new JobTaskMonitor();
  private final long enqueuedAt;
  private volatile String state = "queued";
  private volatile long startedAt;
  private volatile long finishedAt;
  private volatile String error;
  JobResultStore.Entry result;

  JobRecord(String id, String command) {
    this.id = id;
    this.command = command;
    this.enqueuedAt = System.currentTimeMillis();
  }

  void start() {
    state = "running";
    startedAt = System.currentTimeMillis();
  }

  void finish(boolean failed, String failure) {
    state =
        (monitor.wasCancelRequested() || monitor.isCancelled())
            ? (failed ? "cancelled" : "completed_after_cancel")
            : (failed ? "failed" : "complete");
    error = failure;
    finishedAt = System.currentTimeMillis();
  }

  void requestCancellation() {
    state = "cancel_requested";
    monitor.markCancellationRequested();
  }

  void cancelBeforeExecution() {
    monitor.requestCancellation();
    state = "cancelled";
    finishedAt = System.currentTimeMillis();
    error = "Cancelled before execution";
  }

  String state() {
    return state;
  }

  String error() {
    return error;
  }

  long finishedAt() {
    return finishedAt;
  }

  JsonObject toJson(int queuePosition) {
    JsonObject result = new JsonObject();
    result.addProperty("id", id);
    result.addProperty("command", command);
    result.addProperty("state", state);
    JsonObject availability = new JsonObject();
    availability.addProperty("state", "pending");
    result.add("result", this.result == null ? availability : this.result.status());
    result.addProperty("enqueued_at_ms", enqueuedAt);
    if (startedAt > 0) result.addProperty("started_at_ms", startedAt);
    if (finishedAt > 0) result.addProperty("finished_at_ms", finishedAt);
    long end = finishedAt > 0 ? finishedAt : System.currentTimeMillis();
    long start = startedAt > 0 ? startedAt : enqueuedAt;
    result.addProperty("elapsed_ms", Math.max(0, end - start));
    if (queuePosition >= 0) result.addProperty("queue_position", queuePosition);
    result.addProperty("cancel_requested", monitor.wasCancelRequested() || monitor.isCancelled());
    result.addProperty("cancel_enabled", monitor.isCancelEnabled());
    result.addProperty("progress", monitor.getProgress());
    result.addProperty("maximum", monitor.getMaximum());
    result.addProperty("indeterminate", monitor.isIndeterminate());
    String message = monitor.getMessage();
    if (message != null && !message.isEmpty()) result.addProperty("progress_message", message);
    if (error != null) result.addProperty("error", error);
    return result;
  }
}
