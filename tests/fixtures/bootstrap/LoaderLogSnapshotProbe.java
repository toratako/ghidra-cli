
import ghidra.app.script.GhidraScript;
import ghidra.app.util.importer.MessageLog;
import com.google.gson.JsonArray;
import java.nio.file.Files;
import java.nio.file.Path;
public class LoaderLogSnapshotProbe extends GhidraScript {
    public void run() throws Exception {
        Class<?> caller = StackWalker.getInstance(StackWalker.Option.RETAIN_CLASS_REFERENCE)
            .walk(frames -> frames.map(StackWalker.StackFrame::getDeclaringClass)
                .filter(type -> type.getSimpleName().equals("ScriptCommands")
                    && type.getPackageName().equals("ghidracli.script"))
                .findFirst().orElseThrow());
        String bridgePackage = caller.getPackageName()
            .substring(0, caller.getPackageName().lastIndexOf('.') + 1);
        Class<?> support = caller.getClassLoader().loadClass(bridgePackage + "project.ImportSupport");
        var snapshot = support.getDeclaredMethod("diagnostics", MessageLog.class);
        snapshot.setAccessible(true);
        var results = new JsonArray();
        MessageLog log = new MessageLog();
        results.add((com.google.gson.JsonObject) snapshot.invoke(null, log));
        log.appendMsg("x".repeat(16_383) + "\ud83d\ude80" + "z".repeat(100_000));
        results.add((com.google.gson.JsonObject) snapshot.invoke(null, log));
        log.clear();
        log.appendMsg("x".repeat(16_382) + "\ud83d\ude80" + "z");
        results.add((com.google.gson.JsonObject) snapshot.invoke(null, log));
        Files.writeString(Path.of(getScriptArgs()[0]), results.toString());
    }
}
