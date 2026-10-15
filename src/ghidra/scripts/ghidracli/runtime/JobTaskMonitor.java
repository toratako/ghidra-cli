package ghidracli.runtime;

import ghidra.util.datastruct.WeakDataStructureFactory;
import ghidra.util.datastruct.WeakSet;
import ghidra.util.task.CancelledListener;
import ghidra.util.task.TaskMonitorAdapter;

/** Progress fields are published to control requests while a program job runs. */
final class JobTaskMonitor extends TaskMonitorAdapter {
  private final WeakSet<CancelledListener> listeners =
      WeakDataStructureFactory.createCopyOnReadWeakSet();
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
    // Status must not wait for cancellation delivery.
    return cancelEnabled;
  }

  @Override
  public void addCancelledListener(CancelledListener listener) {
    listeners.add(listener);
  }

  @Override
  public void removeCancelledListener(CancelledListener listener) {
    listeners.remove(listener);
  }

  @Override
  protected void notifyChangeListeners() {
    // Copy-on-read iteration releases the set's lock before callbacks run.
    // Native cleanup may remove a listener while another waits for this job.
    for (CancelledListener listener : listeners) listener.cancelled();
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
    if (progress > value) progress = value;
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
