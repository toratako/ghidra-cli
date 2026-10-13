public class CheckNameSuggestions extends ghidra.app.script.GhidraScript {
    private void require(boolean condition, String message) {
        if (!condition) throw new IllegalStateException(message);
    }

    private void distance(String left, String right, int expected) {
        for (int maximum = 0; maximum <= 4; maximum++) {
            require(NameSuggestions.withinDistance(left, right, maximum,
                ghidra.util.task.TaskMonitor.DUMMY) == (expected <= maximum),
                "Wrong suggestion threshold: " + maximum);
            require(NameSuggestions.withinDistance(right, left, maximum,
                ghidra.util.task.TaskMonitor.DUMMY) == (expected <= maximum),
                "Asymmetric suggestion threshold: " + maximum);
        }
    }

    @Override
    public void run() {
        distance("kitten", "sitting", 3);
        distance("abcdef", "zabcde", 2);
        distance("abc", "acb", 2);
        distance("abc", "abc", 0);
        distance("a", "", 1);
        distance("", "", 0);
        // Existing matching counts UTF-16 code units, including surrogate pairs.
        distance("😀", "", 2);
        distance("😀", "x", 2);

        String longName = "a".repeat(100_000);
        distance(longName, longName.substring(0, longName.length() - 3) + "xyz", 3);
        distance(longName, longName.substring(0, longName.length() - 4) + "wxyz", 4);
        require(!NameSuggestions.withinDistance(longName, "tiny", 3,
            ghidra.util.task.TaskMonitor.DUMMY), "Length bound accepted a distant name");
        var cancelling = new ghidra.util.task.TaskMonitorAdapter(true) {
            private int checks;
            @Override
            public boolean isCancelled() {
                return ++checks >= 10;
            }
        };
        try {
            NameSuggestions.withinDistance(longName, longName, 3, cancelling);
            throw new IllegalStateException("Suggestion matching ignored cancellation");
        } catch (java.util.concurrent.CancellationException expected) {
            // Cancellation during a long near match must leave later queries usable.
        }
        require(NameSuggestions.withinDistance("function", "functio", 2,
            ghidra.util.task.TaskMonitor.DUMMY), "Fresh suggestion query did not recover");
    }
}
