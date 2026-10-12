package ghidracli.query;

import ghidra.util.task.TaskMonitor;
import java.util.Arrays;
import java.util.concurrent.CancellationException;

public final class NameSuggestions {
    public static boolean withinDistance(String left, String right, int maximum,
            TaskMonitor monitor) {
        checkCancelled(monitor);
        if (maximum < 0) throw new IllegalArgumentException("Maximum distance must be nonnegative");
        int n = left.length();
        int m = right.length();
        if (Math.abs(n - m) > maximum) return false;
        if (maximum >= Math.max(n, m)) return true;
        if (m > n) return withinDistance(right, left, maximum, monitor);

        // Callers only need small suggestion thresholds. Keep two rows and
        // evaluate the diagonal band that can still meet that threshold.
        int outside = maximum + 1;
        int[] previous = new int[m + 1];
        int[] current = new int[m + 1];
        Arrays.fill(previous, outside);
        Arrays.fill(current, outside);
        for (int j = 0; j <= Math.min(m, maximum); j++) previous[j] = j;
        for (int i = 1; i <= n; i++) {
            checkCancelled(monitor);
            int start = Math.max(1, i - maximum);
            int end = (int) Math.min(m, (long) i + maximum);
            current[start - 1] = start == 1 ? Math.min(i, outside) : outside;
            int minimum = current[start - 1];
            for (int j = start; j <= end; j++) {
                int cost = left.charAt(i - 1) == right.charAt(j - 1) ? 0 : 1;
                current[j] = Math.min(previous[j - 1] + cost,
                    Math.min(previous[j] + 1, current[j - 1] + 1));
                minimum = Math.min(minimum, current[j]);
            }
            if (minimum > maximum) return false;
            if (end < m) current[end + 1] = outside;
            int[] swap = previous;
            previous = current;
            current = swap;
        }
        checkCancelled(monitor);
        return previous[m] <= maximum;
    }

    private static void checkCancelled(TaskMonitor monitor) {
        if (monitor.isCancelled()) throw new CancellationException("Command cancelled");
    }
}
