package ghidracli;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import ghidra.app.util.importer.AutoImporter;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectData;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.task.TaskMonitor;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import static ghidracli.JsonProtocol.errorResult;
import static ghidracli.JsonProtocol.getArgString;

final class ProgramCommands {
    private final ProgramSession session;

    ProgramCommands(ProgramSession session) {
        this.session = session;
    }

    JsonObject handleProgramInfo() {
        if (session.program() == null) {
            return errorResult("No program loaded");
        }

        JsonObject result = new JsonObject();
        result.addProperty("name", session.program().getName());
        result.addProperty("executable_path", session.program().getExecutablePath());
        result.addProperty("executable_format", session.program().getExecutableFormat());
        String compiler = session.program().getCompiler();
        if (compiler != null && !compiler.isEmpty()) {
            result.addProperty("compiler", compiler);
        } else {
            result.add("compiler", JsonNull.INSTANCE);
        }
        result.addProperty("language", session.program().getLanguage().toString());
        result.addProperty("image_base", session.program().getImageBase().toString());
        result.addProperty("min_address", session.program().getMinAddress().toString());
        result.addProperty("max_address", session.program().getMaxAddress().toString());

        FunctionManager fm = session.program().getFunctionManager();
        result.addProperty("function_count", fm.getFunctionCount());

        return result;
    }

    JsonObject handleImport(JsonObject args) {
        String binaryPath = getArgString(args, "binary_path");
        if (binaryPath == null || binaryPath.isEmpty()) {
            return errorResult("No binary_path provided");
        }

        String programName = getArgString(args, "program");
        File binaryFile = new File(binaryPath);
        if (programName == null || programName.isEmpty()) {
            programName = binaryFile.getName();
        }

        Project project = session.state().getProject();
        if (project == null) {
            return errorResult("No project open");
        }

        if (!binaryFile.exists()) {
            return errorResult("Binary file not found: " + binaryPath);
        }

        try {
            TaskMonitor mon = session.monitor();
            MessageLog log = new MessageLog();
            Object consumer = project;

            // Ghidra 12+ API: importByUsingBestGuess(File, Project, String, Object, MessageLog, TaskMonitor)
            Object loadResults = AutoImporter.importByUsingBestGuess(
                binaryFile, project, "/", consumer, log, mon
            );

            if (loadResults == null) {
                return errorResult("Failed to import binary");
            }

            // Save and release - loadResults is a LoadResults<Program>
            // Use reflection to handle API differences across Ghidra versions
            try {
                java.lang.reflect.Method saveMethod = loadResults.getClass().getMethod("save", TaskMonitor.class);
                // Actually it's per-loaded item; iterate
                // LoadResults implements Iterable<Loaded<DomainObject>>
                if (loadResults instanceof Iterable) {
                    for (Object loaded : (Iterable<?>) loadResults) {
                        java.lang.reflect.Method saveMeth = loaded.getClass().getMethod("save", TaskMonitor.class);
                        saveMeth.invoke(loaded, mon);
                    }
                }
                java.lang.reflect.Method releaseMethod = loadResults.getClass().getMethod("release", Object.class);
                releaseMethod.invoke(loadResults, consumer);
            } catch (Exception reflectEx) {
                // Preserve the existing best-effort save behavior.
                session.logError("Import save warning: " + reflectEx.getMessage());
            }

            JsonObject result = new JsonObject();
            result.addProperty("status", "success");
            result.addProperty("program", programName);
            return result;

        } catch (Exception e) {
            return errorResult("Import failed: " + e.getMessage());
        }
    }

    JsonObject handleAnalyze(JsonObject args) {
        String programName = getArgString(args, "program");
        boolean selectProgram = programName != null && !programName.isEmpty();
        if (programName == null || programName.isEmpty()) {
            if (session.program() == null) {
                return errorResult("No program loaded. Use 'open_program' or 'import' first.");
            }
            programName = session.program().getName();
        }

        if (session.program() == null) {
            return errorResult("No program currently loaded");
        }

        // Resolve an explicit selection by project file, not the internal name.
        if (selectProgram) {
            JsonObject switchArgs = new JsonObject();
            switchArgs.addProperty("program", programName);
            JsonObject switchResult = handleOpenProgram(switchArgs);
            if (switchResult.has("error")) {
                return switchResult;
            }
        }

        try {
            TaskMonitor mon = session.monitor();

            // Use GhidraScript's built-in analyzeAll which works across Ghidra versions
            session.analyzeAll(session.program());

            // Explicitly opened programs may save here. The initially loaded
            // program still has the harness's outer transaction; its durable
            // save happens when the bridge script returns.
            try {
                session.program().save("Analysis complete", mon);
            } catch (Exception saveErr) {
                // Best effort - durable persistence also happens on clean shutdown.
            }

            FunctionManager fm = session.program().getFunctionManager();
            JsonObject result = new JsonObject();
            result.addProperty("status", "success");
            result.addProperty("program", programName);
            result.addProperty("function_count", fm.getFunctionCount());
            return result;

        } catch (Exception e) {
            return errorResult("Analysis failed: " + e.getMessage());
        }
    }

    JsonObject handleListPrograms() {
        Project project = session.state().getProject();
        if (project == null) {
            return errorResult("No project open");
        }

        try {
            ProjectData projectData = project.getProjectData();
            DomainFolder rootFolder = projectData.getRootFolder();
            JsonArray programs = new JsonArray();

            for (DomainFile domainFile : rootFolder.getFiles()) {
                boolean isCurrent = session.isCurrent(domainFile);

                JsonObject prog = new JsonObject();
                prog.addProperty("name", domainFile.getName());
                prog.addProperty("path", domainFile.getPathname());
                prog.addProperty("type", domainFile.getContentType());
                prog.addProperty("version", domainFile.getVersion());
                prog.addProperty("current", isCurrent);

                // Add analysis metadata
                if (isCurrent && session.program() != null) {
                    // For current program, use live data
                    FunctionManager fm = session.program().getFunctionManager();
                    int funcCount = fm.getFunctionCount();
                    prog.addProperty("function_count", funcCount);
                    prog.addProperty("analyzed", funcCount > 1);
                    prog.addProperty("executable_format", session.program().getExecutableFormat());
                } else {
                    // For other programs, use DomainFile metadata
                    try {
                        java.util.Map<String, String> metadata = domainFile.getMetadata();
                        if (metadata != null) {
                            String funcCountStr = metadata.get("# of Functions");
                            int funcCount = 0;
                            if (funcCountStr != null) {
                                try { funcCount = Integer.parseInt(funcCountStr.trim()); }
                                catch (NumberFormatException ignored) {}
                            }
                            prog.addProperty("function_count", funcCount);
                            prog.addProperty("analyzed", funcCount > 1);
                            String exeFmt = metadata.get("Executable Format");
                            if (exeFmt != null) {
                                prog.addProperty("executable_format", exeFmt);
                            }
                        }
                    } catch (Exception ignored) {
                        // metadata not available for this file
                    }
                }

                programs.add(prog);
            }

            JsonObject result = new JsonObject();
            result.add("programs", programs);
            result.addProperty("count", programs.size());
            result.addProperty("has_current_program", session.program() != null);
            if (session.program() != null) {
                result.addProperty("current_program_name", session.program().getName());
            }
            return result;

        } catch (Exception e) {
            return errorResult("Failed to list programs: " + e.getMessage());
        }
    }

    JsonObject handleOpenProgram(JsonObject args) {
        String programName = getArgString(args, "program");
        if (programName == null || programName.isEmpty()) {
            return errorResult("Program name required");
        }

        Project project = session.state().getProject();
        if (project == null) {
            return errorResult("No project open");
        }

        try {
            ProjectData projectData = project.getProjectData();
            DomainFolder rootFolder = projectData.getRootFolder();

            // Find the domain file by name
            DomainFile domainFile = null;
            for (DomainFile f : rootFolder.getFiles()) {
                if (f.getName().equals(programName)) {
                    domainFile = f;
                    break;
                }
            }

            if (domainFile == null) {
                // Try as a path
                String path = programName.startsWith("/") ? programName : "/" + programName;
                domainFile = projectData.getFile(path);
            }

            if (domainFile == null) {
                // Build list of available programs for error message
                StringBuilder available = new StringBuilder();
                for (DomainFile f : rootFolder.getFiles()) {
                    if (available.length() > 0) available.append(", ");
                    available.append(f.getName());
                }
                return errorResult("Program not found: " + programName +
                    ". Available: " + available.toString());
            }

            session.open(domainFile, project);

            JsonObject result = new JsonObject();
            result.addProperty("status", "success");
            result.addProperty("program", session.program().getName());
            return result;

        } catch (Exception e) {
            return errorResult("Failed to open program: " + e.getMessage());
        }
    }

    JsonObject handleProgramClose() {
        if (session.program() == null) {
            return errorResult("No program loaded");
        }

        String programName = session.program().getName();

        session.closeProgram();

        JsonObject result = new JsonObject();
        result.addProperty("status", "closed");
        result.addProperty("program", programName);
        result.addProperty("note", "not saved to disk -- run `ghidra program save` or `ghidra stop` to persist pending changes");
        return result;
    }

    JsonObject handleProgramDelete(JsonObject args) {
        String programName = getArgString(args, "program");
        if (programName == null || programName.isEmpty()) {
            return errorResult("Program name required");
        }

        Project project = session.state().getProject();
        if (project == null) {
            return errorResult("No project open");
        }

        try {
            ProjectData projectData = project.getProjectData();
            String path = programName.startsWith("/") ? programName : "/" + programName;
            DomainFile programFile = projectData.getFile(path);

            if (programFile == null) {
                return errorResult("Program not found: " + programName);
            }

            programFile.delete();

            JsonObject result = new JsonObject();
            result.addProperty("status", "deleted");
            result.addProperty("program", programName);
            return result;

        } catch (Exception e) {
            return errorResult("Failed to delete program: " + e.getMessage());
        }
    }

    JsonObject handleProgramExport(JsonObject args) {
        if (session.program() == null) {
            return errorResult("No program loaded");
        }

        String exportFormat = getArgString(args, "format");
        if (exportFormat == null) exportFormat = "json";
        String outputPath = getArgString(args, "output");

        if ("json".equals(exportFormat)) {
            // Get program info as base
            JsonObject data = handleProgramInfo();
            if (data.has("error")) {
                return data;
            }

            // Add function list
            FunctionManager fm = session.program().getFunctionManager();
            JsonArray functions = new JsonArray();
            FunctionIterator iter = fm.getFunctions(true);
            while (iter.hasNext()) {
                Function func = iter.next();
                JsonObject funcObj = new JsonObject();
                funcObj.addProperty("name", func.getName());
                funcObj.addProperty("address", func.getEntryPoint().toString());
                funcObj.addProperty("size", func.getBody().getNumAddresses());
                functions.add(funcObj);
            }
            data.add("functions", functions);

            if (outputPath != null && !outputPath.isEmpty()) {
                try (PrintWriter pw = new PrintWriter(new FileWriter(outputPath))) {
                    Gson prettyGson = new GsonBuilder().setPrettyPrinting().create();
                    pw.println(prettyGson.toJson(data));

                    JsonObject result = new JsonObject();
                    result.addProperty("status", "exported");
                    result.addProperty("format", "json");
                    result.addProperty("output", outputPath);
                    return result;
                } catch (IOException e) {
                    return errorResult("Failed to write file: " + e.getMessage());
                }
            } else {
                return data;
            }
        } else {
            // Resolve a built-in exporter class from the requested format.
            if (outputPath == null || outputPath.isEmpty()) {
                return errorResult("Output path required for format: " + exportFormat);
            }
            try {
                // Map short format codes to the concrete Ghidra Exporter classes.
                // Instantiating the class directly avoids depending on a registry
                // lookup API whose name has changed across Ghidra versions.
                java.util.Map<String, String> classMap = new java.util.HashMap<>();
                classMap.put("xml", "ghidra.app.util.exporter.XmlExporter");
                classMap.put("c", "ghidra.app.util.exporter.CppExporter");
                classMap.put("cpp", "ghidra.app.util.exporter.CppExporter");
                classMap.put("binary", "ghidra.app.util.exporter.BinaryExporter");
                classMap.put("bin", "ghidra.app.util.exporter.BinaryExporter");
                classMap.put("gzf", "ghidra.app.util.exporter.GzfExporter");
                classMap.put("asm", "ghidra.app.util.exporter.AsciiExporter");
                classMap.put("ascii", "ghidra.app.util.exporter.AsciiExporter");
                classMap.put("hex", "ghidra.app.util.exporter.IntelHexExporter");
                classMap.put("html", "ghidra.app.util.exporter.HtmlExporter");

                String className = classMap.get(exportFormat.toLowerCase());
                if (className == null) {
                    return errorResult("Unsupported export format: " + exportFormat
                        + " (supported: json, xml, c, binary, gzf, ascii/asm, hex, html)");
                }

                Class<?> exporterClass = Class.forName(className);
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
                exportMethod.invoke(exporter, new File(outputPath), session.program(), null, mon);

                JsonObject result = new JsonObject();
                result.addProperty("status", "exported");
                result.addProperty("format", exportFormat);
                result.addProperty("output", outputPath);
                return result;
            } catch (Exception e) {
                return errorResult("Failed to export (" + exportFormat + "): " + e.getMessage());
            }
        }
    }

    JsonObject handleStats() {
        if (session.program() == null) return errorResult("No program loaded");

        try {
            FunctionManager fm = session.program().getFunctionManager();
            SymbolTable symbolTable = session.program().getSymbolTable();
            Memory memory = session.program().getMemory();
            DataTypeManager dtm = session.program().getDataTypeManager();
            Listing listing = session.program().getListing();

            int functionCount = fm.getFunctionCount();

            int symbolCount = 0;
            SymbolIterator symIter = symbolTable.getAllSymbols(true);
            while (symIter.hasNext()) { symIter.next(); symbolCount++; }

            int stringCount = 0;
            DataIterator dataIter = listing.getDefinedData(true);
            while (dataIter.hasNext()) {
                if (dataIter.next().hasStringValue()) stringCount++;
            }

            long memorySize = 0;
            int sectionCount = 0;
            for (MemoryBlock block : memory.getBlocks()) {
                memorySize += block.getSize();
                sectionCount++;
            }

            int importCount = 0;
            SymbolIterator extSyms = symbolTable.getExternalSymbols();
            while (extSyms.hasNext()) { extSyms.next(); importCount++; }

            int exportCount = 0;
            ghidra.program.model.address.AddressIterator epIter = symbolTable.getExternalEntryPointIterator();
            while (epIter.hasNext()) { epIter.next(); exportCount++; }

            int dataTypeCount = dtm.getDataTypeCount(false);

            int instructionCount = 0;
            InstructionIterator instrIter = listing.getInstructions(true);
            while (instrIter.hasNext()) { instrIter.next(); instructionCount++; }

            JsonObject stats = new JsonObject();
            stats.addProperty("functions", functionCount);
            stats.addProperty("symbols", symbolCount);
            stats.addProperty("strings", stringCount);
            stats.addProperty("imports", importCount);
            stats.addProperty("exports", exportCount);
            stats.addProperty("memory_size", memorySize);
            stats.addProperty("sections", sectionCount);
            stats.addProperty("data_types", dataTypeCount);
            stats.addProperty("instructions", instructionCount);
            stats.addProperty("program_name", session.program().getName());
            stats.addProperty("executable_format", session.program().getExecutableFormat());
            String compiler = session.program().getCompiler();
            stats.addProperty("compiler", (compiler != null && !compiler.isEmpty()) ? compiler : "Unknown");

            JsonObject result = new JsonObject();
            result.add("stats", stats);
            return result;
        } catch (Exception e) {
            return errorResult("Failed to gather statistics: " + e.getMessage());
        }
    }
}
