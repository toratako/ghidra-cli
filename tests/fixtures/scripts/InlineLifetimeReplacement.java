import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import generic.jar.ResourceFile;
import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraScriptUtil;
import java.lang.reflect.Proxy;
import java.nio.file.Files;
import java.nio.file.Path;
import org.osgi.framework.Bundle;

/** Replace inline-owned resources, then inspect/recover them from a file bundle. */
public class InlineLifetimeReplacement extends GhidraScript {
  public void run() throws Exception {
    String mode = getScriptArgs()[0];
    Path metadata = Path.of(getScriptArgs()[1]);
    Object host = GhidraScriptUtil.class.getMethod("getBundleHost").invoke(null);
    Class<?> hostType = host.getClass();
    JsonObject info;
    ResourceFile sourceDir;
    if (mode.equals("install-add-failure")) {
      var add =
          java.util.Arrays.stream(hostType.getMethods())
              .filter(method -> method.getName().equals("addListener"))
              .findFirst()
              .orElseThrow();
      Class<?> listenerType = add.getParameterTypes()[0];
      Object listener =
          Proxy.newProxyInstance(
              listenerType.getClassLoader(),
              new Class<?>[] {listenerType},
              (proxy, method, values) -> {
                if (method.getDeclaringClass() == Object.class) {
                  return switch (method.getName()) {
                    case "equals" -> proxy == values[0];
                    case "hashCode" -> System.identityHashCode(proxy);
                    default -> "Inline add failure listener";
                  };
                }
                if (method.getName().equals("bundleAdded")) {
                  ResourceFile added =
                      (ResourceFile) values[0].getClass().getMethod("getFile").invoke(values[0]);
                  if (added.getName().startsWith("ghidra-cli-stdin-script")) {
                    hostType.getMethod("removeListener", listenerType).invoke(host, proxy);
                    JsonObject failed = new JsonObject();
                    failed.addProperty("source_directory", added.getAbsolutePath());
                    Files.writeString(metadata, failed.toString());
                    throw new AssertionError("inline registration listener failure");
                  }
                }
                return null;
              });
      add.invoke(host, listener);
      return;
    }
    if (mode.equals("cleanup-add-failure")) {
      info = JsonParser.parseString(Files.readString(metadata)).getAsJsonObject();
      sourceDir = new ResourceFile(info.get("source_directory").getAsString());
      Object pending =
          hostType.getMethod("getGhidraBundle", ResourceFile.class).invoke(host, sourceDir);
      if (pending == null) throw new AssertionError("Unconfirmed registration was removed");
      if (pending.getClass().getMethod("getOSGiBundle").invoke(pending) != null) {
        throw new AssertionError("Failed registration unexpectedly built a bundle");
      }
      Path source = Path.of(sourceDir.getAbsolutePath()).resolve("InlineLifetimeProbe.java");
      if (!Files.isRegularFile(source)) throw new AssertionError("Unconfirmed source was removed");
      hostType.getMethod("remove", ResourceFile.class).invoke(host, sourceDir);
      Files.delete(source);
      Files.delete(source.getParent());
      return;
    }
    if (mode.equals("registry") || mode.equals("location")) {
      sourceDir = getSourceFile().getParentFile();
      Object own =
          hostType.getMethod("getGhidraBundle", ResourceFile.class).invoke(host, sourceDir);
      Class<?> type = own.getClass();
      Path root = (Path) type.getMethod("getCompiledBundlesDir").invoke(null);
      String hash =
          (String) type.getMethod("sourceDirHash", ResourceFile.class).invoke(null, sourceDir);
      Bundle original = (Bundle) type.getMethod("getOSGiBundle").invoke(own);
      info = new JsonObject();
      info.addProperty("source_directory", sourceDir.getAbsolutePath());
      info.addProperty("compiled_directory", root.resolve(hash).toString());
      Bundle replacement = original;
      if (mode.equals("registry")) {
        hostType.getMethod("remove", ResourceFile.class).invoke(host, sourceDir);
        hostType
            .getMethod("add", ResourceFile.class, boolean.class, boolean.class)
            .invoke(host, sourceDir, true, true);
      } else {
        var context = original.getBundleContext().getBundle(0).getBundleContext();
        String location = original.getLocation();
        original.uninstall();
        replacement = context.installBundle(location);
      }
      info.addProperty("bundle_id", replacement.getBundleId());
      Files.writeString(metadata, info.toString());
      println("replaced " + mode);
      return;
    }
    info = JsonParser.parseString(Files.readString(metadata)).getAsJsonObject();
    sourceDir = new ResourceFile(info.get("source_directory").getAsString());
    Object replacement =
        hostType.getMethod("getGhidraBundle", ResourceFile.class).invoke(host, sourceDir);
    if (replacement == null) throw new AssertionError("Replacement registration was removed");
    Bundle osgi = (Bundle) replacement.getClass().getMethod("getOSGiBundle").invoke(replacement);
    if (osgi == null
        || osgi.getState() == Bundle.UNINSTALLED
        || osgi.getBundleId() != info.get("bundle_id").getAsLong()) {
      throw new AssertionError("Replacement OSGi bundle was removed");
    }
    Path source = Path.of(sourceDir.getAbsolutePath()).resolve("InlineLifetimeReplacement.java");
    Path compiled = Path.of(info.get("compiled_directory").getAsString());
    if (!Files.isRegularFile(source)
        || !Files.isRegularFile(compiled.resolve("InlineLifetimeReplacement.class"))) {
      throw new AssertionError("Replacement files were removed");
    }
    if (mode.equals("cleanup")) {
      osgi.uninstall();
      replacement.getClass().getMethod("clean").invoke(replacement);
      hostType.getMethod("remove", ResourceFile.class).invoke(host, sourceDir);
      Files.delete(source);
      Files.delete(source.getParent());
      if (Files.exists(compiled)) throw new AssertionError("Recovery retained compiled files");
    }
    println("replacement " + mode + " verified");
  }
}
