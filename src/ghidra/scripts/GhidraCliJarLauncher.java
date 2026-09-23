import java.nio.file.Path;

import com.google.gson.Gson;

import ghidra.JarRun;

/** Preserves Unicode paths and arguments across the Windows Java launcher. */
public class GhidraCliJarLauncher {
    public static void main(String[] ignored) throws Exception {
        String encoded = System.getenv("GHIDRA_CLI_JAR_ARGUMENTS");
        if (encoded == null) {
            throw new IllegalStateException("Missing Ghidra JAR launch arguments");
        }
        String[] arguments = new Gson().fromJson(encoded, String[].class);
        // The manifest loads Ghidra in the system classloader. Keep Ghidra's
        // classpath/resource discovery pointed at the original standalone JAR.
        Path jar = Path.of(JarRun.class.getProtectionDomain().getCodeSource().getLocation().toURI());
        System.setProperty("java.class.path", jar.toString());
        JarRun.main(arguments);
    }
}
