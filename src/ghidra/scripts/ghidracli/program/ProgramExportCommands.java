package ghidracli.program;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import ghidra.app.util.exporter.Exporter;
import ghidra.util.task.TaskMonitor;
import ghidracli.session.ProgramSession;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;

import static ghidracli.protocol.JsonProtocol.errorResult;
import static ghidracli.protocol.JsonProtocol.getArgString;

public final class ProgramExportCommands {
    private final ProgramSession session;

    public ProgramExportCommands(ProgramSession session) {
        this.session = session;
    }

    public JsonObject handleProgramExport(JsonObject args) {
        if (session.program() == null) {
            return errorResult("No program loaded");
        }

        String exportFormat = getArgString(args, "format");
        if (exportFormat == null || exportFormat.isEmpty()) {
            return errorResult("Export format required");
        }
        String outputPath = getArgString(args, "output");

        try {
            // Map short format codes to the concrete Ghidra Exporter classes.
            // Instantiating the class directly avoids depending on a registry
            // lookup API whose name has changed across Ghidra versions.
            java.util.Map<String, String> classMap = new java.util.HashMap<>();
            classMap.put("xml", "ghidra.app.util.exporter.XmlExporter");
            classMap.put("c", "ghidra.app.util.exporter.CppExporter");
            classMap.put("binary", "ghidra.app.util.exporter.BinaryExporter");
            classMap.put("gzf", "ghidra.app.util.exporter.GzfExporter");
            classMap.put("asm", "ghidra.app.util.exporter.AsciiExporter");
            classMap.put("hex", "ghidra.app.util.exporter.IntelHexExporter");
            classMap.put("html", "ghidra.app.util.exporter.HtmlExporter");

            String className = classMap.get(exportFormat.toLowerCase(java.util.Locale.ROOT));
            if (className == null) {
                return errorResult("Unsupported export format: " + exportFormat
                    + " (supported: xml, c, binary, gzf, asm, hex, html)");
            }

            if (outputPath == null || outputPath.isEmpty()) {
                return errorResult("Output path required for format: " + exportFormat);
            }

            // Keep the exporter package in this bundle's OSGi imports even
            // though the concrete class name is selected dynamically.
            Class<?> exporterClass = Class.forName(className, true, Exporter.class.getClassLoader());
            Object exporter = exporterClass.getDeclaredConstructor().newInstance();

            // Resolve export(File, DomainObject, AddressSetView, TaskMonitor) by
            // name + arity to tolerate signature drift across Ghidra versions.
            java.lang.reflect.Method exportMethod = null;
            for (java.lang.reflect.Method m : exporterClass.getMethods()) {
                if (m.getName().equals("export") && m.getParameterCount() == 4) {
                    exportMethod = m;
                    break;
                }
            }
            if (exportMethod == null) {
                return errorResult("Exporter has no 4-arg export method: " + exportFormat);
            }

            TaskMonitor mon = session.monitor();
            Object exported;
            if ("gzf".equalsIgnoreCase(exportFormat)) {
                session.save();
                Path destination = new File(outputPath).toPath().toAbsolutePath();
                // GzfExporter deletes its output before writing it. Keep that
                // file in a private directory beside the destination, and only
                // replace the destination once packing has fully succeeded.
                Path staging = Files.createTempDirectory(destination.getParent(), ".ghidra-cli-gzf-");
                Path packed = staging.resolve("program.gzf");
                try {
                    exported = exportMethod.invoke(exporter, packed.toFile(), session.program(), null, mon);
                    if (Boolean.TRUE.equals(exported)) {
                        mon.checkCancelled();
                        Files.move(packed, destination, StandardCopyOption.ATOMIC_MOVE,
                            StandardCopyOption.REPLACE_EXISTING);
                    }
                } finally {
                    try {
                        Files.deleteIfExists(packed);
                    } finally {
                        Files.deleteIfExists(staging);
                    }
                }
            } else {
                exported = exportMethod.invoke(exporter, new File(outputPath), session.program(), null, mon);
            }
            if (!Boolean.TRUE.equals(exported)) {
                Object log = exporterClass.getMethod("getMessageLog").invoke(exporter);
                return errorResult("Failed to export (" + exportFormat + "): " + log);
            }

            JsonObject result = new JsonObject();
            result.addProperty("status", "exported");
            result.addProperty("format", exportFormat);
            result.addProperty("output", outputPath);
            result.addProperty("program_path", session.programPath());
            // A null address selection requests the program, but each native
            // exporter decides what it can represent. It is not a coverage check.
            result.addProperty("requested_scope", "program");
            result.add("artifacts", exportArtifacts(exportFormat, outputPath));
            JsonArray messages = new JsonArray();
            Object log = exporterClass.getMethod("getMessageLog").invoke(exporter);
            if (log != null && !log.toString().isBlank()) messages.add(log.toString());
            result.add("exporter_messages", messages);
            result.add("limitations", exportLimitations(exportFormat));
            return result;
        } catch (Exception e) {
            Throwable cause = e instanceof java.lang.reflect.InvocationTargetException
                && e.getCause() != null ? e.getCause() : e;
            return errorResult("Failed to export (" + exportFormat + "): " + cause.getMessage());
        }
    }

    private static JsonArray exportArtifacts(String format, String outputPath) throws IOException {
        JsonArray artifacts = new JsonArray();
        Path output = new File(outputPath).toPath().toAbsolutePath();
        artifacts.add(exportArtifact(output));
        if ("xml".equalsIgnoreCase(format)) {
            // XmlExporter defaults to memory contents. MemoryMapXmlMgr creates
            // this file on every export, even when no initialized bytes exist.
            String name = output.getFileName().toString();
            if (name.endsWith(".xml")) name = name.substring(0, name.length() - 4);
            artifacts.add(exportArtifact(output.resolveSibling(name + ".bytes")));
        }
        return artifacts;
    }

    private static JsonObject exportArtifact(Path path) throws IOException {
        if (!Files.isRegularFile(path)) {
            throw new IOException("Exporter did not create an output file: " + path);
        }
        JsonObject artifact = new JsonObject();
        artifact.addProperty("path", path.toString());
        artifact.addProperty("size_bytes", Files.size(path));
        return artifact;
    }

    private static JsonArray exportLimitations(String format) {
        JsonArray limitations = new JsonArray();
        switch (format.toLowerCase(java.util.Locale.ROOT)) {
            case "c":
                limitations.add("Function bodies depend on successful decompilation; export success does not verify complete function coverage.");
                limitations.add("Global declarations describe referenced globals and do not preserve original data initializers. Use data read or memory read to inspect values.");
                limitations.add("Exporter messages do not include every decompiler diagnostic; inspect the generated C for diagnostic comments.");
                break;
            case "binary":
                limitations.add("Initialized memory ranges are concatenated without address gaps or metadata; this is not the original executable file layout.");
                break;
            case "xml":
                limitations.add("Memory contents are stored in the companion .bytes artifact; keep it with the XML file.");
                break;
            case "asm":
            case "html":
                limitations.add("The output is a formatted listing, not a restorable program database.");
                break;
            case "hex":
                limitations.add("Only initialized memory in the default address space is represented.");
                break;
            default:
                break;
        }
        return limitations;
    }
}
