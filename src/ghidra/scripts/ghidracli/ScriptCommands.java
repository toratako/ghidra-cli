package ghidracli;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import generic.jar.ResourceFile;
import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraScriptLoadException;
import ghidra.app.script.GhidraScriptProvider;
import ghidra.app.script.GhidraScriptUtil;
import ghidra.app.script.GhidraState;
import ghidra.util.exception.CancelledException;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.osgi.framework.Bundle;
import static ghidracli.JsonProtocol.errorResult;
import static ghidracli.JsonProtocol.getArgString;
import static ghidracli.JsonProtocol.getArgStringArray;
import static ghidracli.JsonProtocol.toJsonArray;

final class ScriptCommands {
    private final ProgramSession session;
    private final ArtifactManifest artifacts;

    ScriptCommands(ProgramSession session, ArtifactManifest artifacts) {
        this.session = session;
        this.artifacts = artifacts;
    }

    JsonObject handleScriptRun(JsonObject args) {
        String scriptPath = getArgString(args, "path");
        String inlineSource = getArgString(args, "source");
        if ((scriptPath == null || scriptPath.isEmpty()) && (inlineSource == null || inlineSource.isEmpty())) {
            return errorResult("Script path or inline source required");
        }

        File scriptFile;
        File tempDir = null;
        if (inlineSource != null && !inlineSource.isEmpty()) {
            // Stdin-sourced one-offs (`ghidra script run -`): stage the source into a
            // temp file and run it through the exact same compile/execute path as a
            // file on disk, rather than eval'ing it directly -- this is what keeps
            // inline snippets going through Ghidra's normal script bundle/compile gate
            // instead of adding a second, less-sandboxed execution path.
            Matcher classMatch = Pattern.compile("public\\s+class\\s+(\\w+)").matcher(inlineSource);
            if (!classMatch.find()) {
                return errorResult("Inline script source must define `public class <Name> extends GhidraScript`");
            }
            String className = classMatch.group(1);
            try {
                tempDir = java.nio.file.Files.createTempDirectory("ghidra-cli-stdin-script").toFile();
                scriptFile = new File(tempDir, className + ".java");
                try (FileWriter fw = new FileWriter(scriptFile)) {
                    fw.write(inlineSource);
                }
            } catch (IOException e) {
                return errorResult("Failed to stage inline script: " + e.getMessage());
            }
        } else {
            // Resolve to an absolute path so the script is found regardless of the
            // working directory the bridge JVM inherited. This removes the RE-repo
            // workaround of copying scripts into a global scripts directory.
            scriptFile = new File(scriptPath).getAbsoluteFile();
            if (!scriptFile.exists()) return errorResult("Script not found: " + scriptFile.getPath());
        }
        final File cleanupTempDir = tempDir;

        String[] scriptArgs = getArgStringArray(args, "args");
        ResourceFile source = new ResourceFile(scriptFile);
        ResourceFile sourceDir = source.getParentFile();

        StringWriter buffer = new StringWriter();
        PrintWriter out = new PrintWriter(buffer);
        try {
            // A script only resolves if its parent directory is a registered
            // bundle/source directory. Register it if it is not already.
            //
            // Done via reflection on purpose: referencing BundleHost/GhidraBundle
            // directly -- even Class.forName() with a literal class-name string --
            // makes bnd's OSGi Import-Package analysis add ghidra.app.plugin.core.osgi
            // as a hard dependency of the bridge's own bundle, which the bridge
            // cannot wire, so the whole bridge fails to load. Every reflective type
            // token below is obtained via .getClass() on an already-held instance
            // instead, exactly like the getBundleHost()/bhClass pair here already
            // did. handleScriptList() uses the same .getClass() pattern.
            Object bundleHost = GhidraScriptUtil.class
                .getMethod("getBundleHost").invoke(null);
            if (bundleHost == null) return errorResult("Ghidra script bundle host unavailable");
            Class<?> bhClass = bundleHost.getClass();
            // getGhidraBundle() is a plain map lookup; getExistingGhidraBundle()
            // is for callers who expect the bundle to already exist and logs an
            // ERROR to application.log on a miss -- which is exactly what happens
            // here on every first-ever run of a script in a new directory. Using
            // getGhidraBundle() for this existence check avoids that misleading
            // (and otherwise benign) log noise.
            Object bundle = bhClass
                .getMethod("getGhidraBundle", ResourceFile.class)
                .invoke(bundleHost, sourceDir);
            if (bundle == null) {
                // enabled=true: matches how Ghidra's own script manager registers
                // a directory a user actually wants to run scripts from.
                bundle = bhClass.getMethod("add", ResourceFile.class, boolean.class, boolean.class)
                    .invoke(bundleHost, sourceDir, true, true);
            }
            if (bundle == null) {
                return errorResult("Failed to register script bundle for " + sourceDir.getAbsolutePath());
            }

            GhidraScriptProvider provider = GhidraScriptUtil.getProvider(source);
            if (provider == null) {
                return errorResult("No script provider for " + scriptFile.getName()
                    + " (unsupported script type)");
            }

            GhidraScript script;
            if (scriptFile.getName().endsWith(".java")) {
                // Build and load the class from the EXACT bundle we just resolved
                // above, rather than delegating to provider.getScriptInstance(),
                // which internally re-resolves the bundle via
                // GhidraScriptUtil.findSourceDirectoryContaining(). That lookup
                // returns the FIRST registered source directory that is an
                // ancestor of the script -- not necessarily the most specific
                // one -- so when a broader, unrelated ancestor directory is also
                // registered as a bundle (e.g. from a prior `script run`/`script
                // list` against a sibling or parent project), it can silently
                // resolve to the WRONG bundle: either failing outright with
                // "Failed to get OSGi bundle containing script" because the
                // class isn't there, or worse, loading a same-named class from
                // the wrong bundle entirely. Pinning to `bundle` here sidesteps
                // that ambiguity altogether.
                Class<?> bundleClass = bundle.getClass();
                try {
                    bundleClass.getMethod("build", PrintWriter.class).invoke(bundle, out);
                    String locationId = (String) bundleClass
                        .getMethod("getLocationIdentifier").invoke(bundle);
                    bhClass.getMethod("activateSynchronously", String.class)
                        .invoke(bundleHost, locationId);
                } catch (java.lang.reflect.InvocationTargetException ite) {
                    Throwable cause = ite.getCause() != null ? ite.getCause() : ite;
                    out.flush();
                    return errorResult("Script failed to build: " + cause.getMessage()
                        + (buffer.getBuffer().length() > 0 ? "\n" + buffer : ""));
                }

                // Typed as the org.osgi.framework.Bundle interface (not the
                // concrete Felix impl class .getOSGiBundle() actually returns):
                // reflectively invoking loadClass() via the concrete class's own
                // Method object throws IllegalAccessException, because that
                // class isn't public even though the method is -- the standard
                // reflection gotcha for "public method of non-public class".
                // Going through the public Bundle interface sidesteps it.
                Object rawOsgiBundle = bundleClass.getMethod("getOSGiBundle").invoke(bundle);
                if (rawOsgiBundle == null) {
                    out.flush();
                    return errorResult("Failed to get OSGi bundle containing script: "
                        + scriptFile.getPath()
                        + (buffer.getBuffer().length() > 0 ? "\n" + buffer : ""));
                }
                Bundle osgiBundle = (Bundle) rawOsgiBundle;
                String className = (String) bundleClass
                    .getMethod("classNameForScript", ResourceFile.class)
                    .invoke(bundle, source);
                Class<?> loadedClass;
                try {
                    loadedClass = osgiBundle.loadClass(className);
                } catch (ClassNotFoundException cnfe) {
                    return errorResult("The class could not be found. It must be the public "
                        + "class of the .java file: " + cnfe.getMessage());
                }
                if (!GhidraScript.class.isAssignableFrom(loadedClass)) {
                    return errorResult("Loaded class " + className + " does not extend GhidraScript");
                }
                script = (GhidraScript) loadedClass.getDeclaredConstructor().newInstance();
                script.setSourceFile(source);
            } else {
                // Non-Java providers (e.g. Python) aren't resolved via the OSGi
                // bundle path above; fall back to the provider's own resolution.
                script = provider.getScriptInstance(source, out);
            }
            script.setScriptArgs(scriptArgs);

            // Run on the program executor's exclusive objects. `monitor` is the
            // per-job cancellable JobTaskMonitor installed in executeProgramJob,
            // so cancel/status work for scripts with no extra machinery.
            //
            // Use the copy constructor rather than the 6-arg form: it only
            // references ghidra.app.script, avoiding OSGi Import-Package entries
            // on ghidra.framework.plugintool / ghidra.program.util that the bridge
            // bundle may not be able to wire.
            if (session.state() == null) return errorResult("Bridge script state unavailable");
            GhidraState scriptState = new GhidraState(session.state());
            scriptState.setCurrentProgram(session.program());
            script.execute(scriptState, session.monitor(), out);
            out.flush();

            JsonObject result = new JsonObject();
            result.addProperty("script", scriptFile.getName());
            result.addProperty("path", scriptFile.getAbsolutePath());
            result.addProperty("stdout", buffer.toString());
            result.add("args", toJsonArray(scriptArgs));

            // Artifact contract: validate declared outputs and fail closed on a
            // missing/empty/under-count artifact, so callers can trust the job
            // succeeded only when its expected records actually exist.
            return artifacts.validateArtifacts(result, args, buffer.toString());
        } catch (GhidraScriptLoadException e) {
            return errorResult("Script failed to compile: " + e.getMessage());
        } catch (CancelledException e) {
            return errorResult("Script cancelled");
        } catch (Exception e) {
            // Preserve any output the script produced before it threw.
            out.flush();
            JsonObject err = errorResult("Script threw: " + e.getMessage());
            err.addProperty("stdout", buffer.toString());
            return err;
        } finally {
            if (cleanupTempDir != null) {
                scriptFile.delete();
                cleanupTempDir.delete();
            }
        }
    }

    JsonObject handleScriptJava(JsonObject args) {
        return errorResult("Inline Java execution (`script java`) is disabled by design: every script, "
            + "including one-offs, is required to go through Ghidra's normal script bundle/compile gate "
            + "(GhidraScriptProvider.getScriptInstance) rather than a second, less-sandboxed eval path. "
            + "For a throwaway snippet without a checked-in file, use `ghidra script run -` and pipe the "
            + "Java source on stdin -- it is staged to a temp file and compiled through the same path.");
    }

    JsonObject handleScriptPython(JsonObject args) {
        return errorResult("Python execution is not available: the Java bridge replaces the old Python "
            + "bridge.py entirely, and there is no embedded Python interpreter in this process. Port the "
            + "logic to a Java GhidraScript and use `ghidra script run PATH`, or `ghidra script run -` "
            + "for a one-off piped via stdin.");
    }

    JsonObject handleScriptList() {
        try {
            JsonArray scripts = new JsonArray();

            // List scripts from Ghidra's script directories
            Class<?> utilClass = Class.forName("ghidra.app.script.GhidraScriptUtil");
            java.lang.reflect.Method getDirs = utilClass.getMethod("getScriptSourceDirectories");
            Object dirs = getDirs.invoke(null);

            if (dirs instanceof Iterable) {
                for (Object dirObj : (Iterable<?>) dirs) {
                    File dir = new File(dirObj.toString());
                    if (dir.exists() && dir.isDirectory()) {
                        for (File f : dir.listFiles()) {
                            if (f.getName().endsWith(".py") || f.getName().endsWith(".java")) {
                                JsonObject scriptObj = new JsonObject();
                                scriptObj.addProperty("name", f.getName());
                                scriptObj.addProperty("path", f.getAbsolutePath());
                                scriptObj.addProperty("type", f.getName().endsWith(".py") ? "python" : "java");
                                scripts.add(scriptObj);
                            }
                        }
                    }
                }
            }

            JsonObject result = new JsonObject();
            result.add("scripts", scripts);
            result.addProperty("count", scripts.size());
            return result;
        } catch (Exception e) {
            return errorResult("Failed to list scripts: " + e.getMessage());
        }
    }
}
