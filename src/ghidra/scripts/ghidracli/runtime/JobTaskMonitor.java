package ghidracli.runtime;

import ghidra.util.task.TaskMonitorAdapter;

/** Progress fields are published to control requests while a program job runs. */
final class JobTaskMonitor extends TaskMonitorAdapter {
  private volatile String message = "";
  private volatile long progress;
  private volatile long maximum;
  private volatile boolean indeterminate;
  private volatile boolean cancelRequested;
  private volatile boolean cancelEnabled = true;

  JobTaskMonitor() {
    super(true);
  }

  boolean wasCancelRequested() {
    return cancelRequested;
  }

  void markCancellationRequested() {
    cancelRequested = true;
  }

  void requestCancellation() {
    markCancellationRequested();
    super.cancel();
  }

  @Override
  public void setCancelEnabled(boolean enabled) {
    super.setCancelEnabled(enabled);
    cancelEnabled = enabled;
    if (enabled && cancelRequested) super.cancel();
  }

  @Override
  public boolean isCancelEnabled() {
    // Native cancellation listeners run while holding the adapter lock.
    // Status must not wait for a listener to finish.
    return cancelEnabled;
  }

  @Override
  public void setMessage(String value) {
    message = value == null ? "" : value;
    super.setMessage(value);
  }

  @Override
  public String getMessage() {
    return message;
  }

  @Override
  public void setProgress(long value) {
    progress = value;
    super.setProgress(value);
  }

  @Override
  public long getProgress() {
    return progress;
  }

  @Override
  public void initialize(long value) {
    maximum = value;
    progress = 0;
    super.initialize(value);
  }

  @Override
  public void setMaximum(long value) {
    maximum = value;
    super.setMaximum(value);
  }

  @Override
  public long getMaximum() {
    return maximum;
  }

  @Override
  public void setIndeterminate(boolean value) {
    indeterminate = value;
    super.setIndeterminate(value);
  }

  @Override
  public boolean isIndeterminate() {
    return indeterminate;
  }

  @Override
  public void incrementProgress(long amount) {
    progress += amount;
    super.incrementProgress(amount);
  }
}
