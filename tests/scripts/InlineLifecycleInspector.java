import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import generic.jar.ResourceFile;
import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraScriptUtil;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collection;
import java.util.TreeSet;
import org.osgi.framework.Bundle;
import org.osgi.framework.wiring.FrameworkWiring;

/** Inspect the native host from a persistent file-script bundle. */
public class InlineLifecycleInspector extends GhidraScript {
    public void run() throws Exception {
        Object host = GhidraScriptUtil.class.getMethod("getBundleHost").invoke(null);
        Class<?> hostType = host.getClass();
        Collection<?> files = (Collection<?>) hostType.getMethod("getBundleFiles").invoke(host);
        TreeSet<String> registered = new TreeSet<>();
        for (Object file : files) registered.add(((ResourceFile) file).getAbsolutePath());
        Object own = hostType.getMethod("getGhidraBundle", ResourceFile.class)
            .invoke(host, getSourceFile().getParentFile());
        Path compiled = (Path) own.getClass().getMethod("getCompiledBundlesDir").invoke(null);
        TreeSet<String> binaries = new TreeSet<>();
        try (var children = Files.list(compiled)) {
            children.forEach(path -> binaries.add(path.getFileName().toString()));
        }
        TreeSet<String> temporary = new TreeSet<>();
        try (var children = Files.list(Path.of(System.getProperty("java.io.tmpdir")))) {
            children.filter(path -> path.getFileName().toString().startsWith("ghidra-cli-stdin-script"))
                .forEach(path -> temporary.add(path.toString()));
        }
        Bundle osgi = (Bundle) own.getClass().getMethod("getOSGiBundle").invoke(own);
        TreeSet<String> installed = new TreeSet<>();
        for (Bundle bundle : osgi.getBundleContext().getBundles()) {
            installed.add(Long.toString(bundle.getBundleId()));
        }
        TreeSet<String> pending = new TreeSet<>();
        FrameworkWiring wiring = osgi.getBundleContext().getBundle(0).adapt(FrameworkWiring.class);
        for (Bundle bundle : wiring.getRemovalPendingBundles()) {
            pending.add(Long.toString(bundle.getBundleId()));
        }
        JsonObject result = new JsonObject();
        result.add("registered", array(registered));
        result.add("compiled", array(binaries));
        result.add("temporary", array(temporary));
        result.add("installed", array(installed));
        result.add("removal_pending", array(pending));
        println("INLINE_LIFECYCLE=" + result);
    }

    private static JsonArray array(Collection<String> values) {
        JsonArray result = new JsonArray();
        for (String value : values) result.add(value);
        return result;
    }
}
