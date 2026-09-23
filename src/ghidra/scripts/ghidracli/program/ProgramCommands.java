package ghidracli.program;

import com.google.gson.JsonArray;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectData;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.reloc.Relocation;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.util.GhidraProgramUtilities;
import ghidra.util.exception.CancelledException;
import ghidracli.project.ImportSupport;
import ghidracli.protocol.JsonProtocol;
import ghidracli.query.AddressCodec;
import ghidracli.session.ProgramSession;
import java.util.HexFormat;
import java.util.Iterator;

import static ghidracli.protocol.JsonProtocol.errorResult;
import static ghidracli.protocol.JsonProtocol.getArgString;

public final class ProgramCommands {
    private final ProgramSession session;

    public ProgramCommands(ProgramSession session) {
        this.session = session;
    }

    public JsonObject handleProgramInfo() {
        if (session.program() == null) {
            return errorResult("No program loaded");
        }

        JsonObject result = new JsonObject();
        result.addProperty("name", session.programName());
        result.addProperty("path", session.programPath());
        result.addProperty("executable_path", session.program().getExecutablePath());
        result.addProperty("executable_format", session.program().getExecutableFormat());
        result.addProperty("executable_md5", executableHash(session.program().getExecutableMD5()));
        result.addProperty("executable_sha256", executableHash(session.program().getExecutableSHA256()));
        String compiler = session.program().getCompiler();
        if (compiler != null && !compiler.isEmpty()) {
            result.addProperty("compiler", compiler);
        } else {
            result.add("compiler", JsonNull.INSTANCE);
        }
        result.addProperty("language", session.program().getLanguage().toString());
        result.addProperty("language_id", session.program().getLanguageID().toString());
        result.addProperty("compiler_spec_id", session.program().getCompilerSpec().getCompilerSpecID().toString());
        result.addProperty("image_base", AddressCodec.format(session.program().getImageBase()));
        result.addProperty("min_address", AddressCodec.format(session.program().getMinAddress()));
        result.addProperty("max_address", AddressCodec.format(session.program().getMaxAddress()));

        FunctionManager fm = session.program().getFunctionManager();
        result.addProperty("function_count", fm.getFunctionCount());

        return result;
    }

    private static String executableHash(String hash) {
        // ProgramDB uses this sentinel when the imported-file metadata is absent.
        return hash == null || hash.isEmpty() || "unknown".equals(hash) ? null : hash;
    }

    public JsonObject handleListCallingConventions() throws CancelledException {
        if (session.program() == null) return errorResult("No program loaded");

        var compilerSpec = session.program().getCompilerSpec();
        var defaultConvention = compilerSpec.getDefaultCallingConvention();
        JsonArray conventions = new JsonArray();
        for (var convention : compilerSpec.getCallingConventions()) {
            session.monitor().checkCancelled();
            JsonObject row = new JsonObject();
            row.addProperty("name", convention.getName());
            row.addProperty("is_default", defaultConvention != null
                && convention.getName().equals(defaultConvention.getName()));
            conventions.add(row);
        }

        JsonObject result = new JsonObject();
        result.add("calling_conventions", conventions);
        result.addProperty("count", conventions.size());
        return result;
    }

    public JsonObject handleListRelocations() throws CancelledException {
        if (session.program() == null) return errorResult("No program loaded");

        JsonArray relocations = new JsonArray();
        Iterator<Relocation> iterator = session.program().getRelocationTable().getRelocations();
        while (iterator.hasNext()) {
            session.monitor().checkCancelled();
            Relocation relocation = iterator.next();
            JsonObject row = new JsonObject();
            row.addProperty("address", AddressCodec.format(relocation.getAddress()));
            row.addProperty("type", relocation.getType());
            row.addProperty("status", relocation.getStatus().name());
            row.addProperty("symbol_name", relocation.getSymbolName());
            long[] values = relocation.getValues();
            if (values == null) {
                row.add("values", JsonNull.INSTANCE);
            } else {
                JsonArray serializedValues = new JsonArray();
                for (long value : values) serializedValues.add(value);
                row.add("values", serializedValues);
            }
            byte[] originalBytes = relocation.getBytes();
            row.addProperty("original_bytes", originalBytes == null
                ? null : HexFormat.of().formatHex(originalBytes));
            relocations.add(row);
        }

        JsonObject result = new JsonObject();
        result.add("relocations", relocations);
        result.addProperty("count", relocations.size());
        return result;
    }

    public JsonObject handleImport(JsonObject args) {
        String binaryPath = getArgString(args, "binary_path");
        if (binaryPath == null || binaryPath.isEmpty()) {
            return errorResult("No binary_path provided");
        }

        Project project = session.state().getProject();
        if (project == null) return errorResult("No project open");
        try {
            return ImportSupport.run(project, args, project, session.monitor(), null);
        } catch (Exception error) {
            return JsonProtocol.errorResult("Import failed: " + error.getMessage(), error);
        }
    }

    public JsonObject handleListPrograms() {
        Project project = session.state().getProject();
        if (project == null) {
            return errorResult("No project open");
        }

        try {
            JsonArray programs = new JsonArray();
            for (DomainFile file : session.programFiles()) programs.add(programMetadata(file));

            JsonObject result = new JsonObject();
            result.add("programs", programs);
            result.addProperty("count", programs.size());
            result.addProperty("has_current_program", session.program() != null);
            if (session.program() != null) {
                result.addProperty("current_program_name", session.programName());
            }
            return result;

        } catch (Exception e) {
            return errorResult("Failed to list programs: " + e.getMessage());
        }
    }

    private JsonObject programMetadata(DomainFile domainFile) throws CancelledException {
        session.monitor().checkCancelled();
        boolean isCurrent = session.isCurrent(domainFile);

        JsonObject prog = new JsonObject();
        prog.addProperty("name", domainFile.getName());
        prog.addProperty("path", domainFile.getPathname());
        prog.addProperty("type", domainFile.getContentType());
        prog.addProperty("version", domainFile.getVersion());
        prog.addProperty("current", isCurrent);
        prog.add("analyzed", JsonNull.INSTANCE);

        // Add analysis metadata
        if (isCurrent && session.program() != null) {
            // For current program, use live data
            FunctionManager fm = session.program().getFunctionManager();
            int funcCount = fm.getFunctionCount();
            prog.addProperty("function_count", funcCount);
            var options = session.program().getOptions(Program.PROGRAM_INFO);
            if (options.contains(Program.ANALYZED_OPTION_NAME)
                    && options.getType(Program.ANALYZED_OPTION_NAME)
                        == ghidra.framework.options.OptionType.BOOLEAN_TYPE) {
                prog.addProperty("analyzed", GhidraProgramUtilities.isAnalyzed(session.program()));
            }
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
                    String analyzed = metadata.get(Program.ANALYZED_OPTION_NAME);
                    if (analyzed != null && ("true".equalsIgnoreCase(analyzed.trim())
                            || "false".equalsIgnoreCase(analyzed.trim()))) {
                        prog.addProperty("analyzed", Boolean.parseBoolean(analyzed.trim()));
                    }
                    String exeFmt = metadata.get("Executable Format");
                    if (exeFmt != null) {
                        prog.addProperty("executable_format", exeFmt);
                    }
                }
            } catch (Exception ignored) {
                // metadata not available for this file
            }
        }

        return prog;
    }

    public JsonObject handleOpenProgram(JsonObject args) {
        String programName = getArgString(args, "program");
        if (programName == null || programName.isEmpty()) {
            return errorResult("Program name required");
        }

        Project project = session.state().getProject();
        if (project == null) {
            return errorResult("No project open");
        }

        try {
            DomainFile domainFile = session.findProgram(programName);
            session.open(domainFile);

            JsonObject result = new JsonObject();
            result.addProperty("status", "success");
            result.addProperty("program", session.programName());
            return result;

        } catch (Exception e) {
            return errorResult("Failed to open program: " + e.getMessage());
        }
    }

    public JsonObject handleProgramSave() {
        JsonObject result = new JsonObject();
        // CommandDispatcher finishes the transaction and saves before replying.
        result.addProperty("saved", session.program() != null);
        if (session.program() != null) result.addProperty("program", session.programName());
        return result;
    }

    public JsonObject handleProgramClose() throws Exception {
        if (session.program() == null) {
            return errorResult("No program loaded");
        }

        String programName = session.programName();

        session.closeProgram();

        JsonObject result = new JsonObject();
        result.addProperty("status", "closed");
        result.addProperty("program", programName);
        result.addProperty("saved", true);
        return result;
    }

    public JsonObject handleProgramDelete(JsonObject args) {
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

            session.delete(programFile);

            JsonObject result = new JsonObject();
            result.addProperty("status", "deleted");
            result.addProperty("program", programName);
            return result;

        } catch (Exception e) {
            return errorResult("Failed to delete program: " + e.getMessage());
        }
    }

    public JsonObject handleStats() throws CancelledException {
        if (session.program() == null) return errorResult("No program loaded");

        try {
            session.monitor().checkCancelled();
            FunctionManager fm = session.program().getFunctionManager();
            SymbolTable symbolTable = session.program().getSymbolTable();
            Memory memory = session.program().getMemory();
            DataTypeManager dtm = session.program().getDataTypeManager();
            Listing listing = session.program().getListing();

            int functionCount = fm.getFunctionCount();

            int symbolCount = 0;
            SymbolIterator symIter = symbolTable.getAllSymbols(true);
            while (symIter.hasNext()) {
                session.monitor().checkCancelled();
                symIter.next();
                symbolCount++;
            }

            int stringCount = 0;
            DataIterator dataIter = listing.getDefinedData(true);
            while (dataIter.hasNext()) {
                session.monitor().checkCancelled();
                if (dataIter.next().hasStringValue()) stringCount++;
            }

            long memorySize = 0;
            int memoryBlockCount = 0;
            for (MemoryBlock block : memory.getBlocks()) {
                session.monitor().checkCancelled();
                memorySize += block.getSize();
                memoryBlockCount++;
            }

            int importCount = 0;
            SymbolIterator extSyms = symbolTable.getExternalSymbols();
            while (extSyms.hasNext()) {
                session.monitor().checkCancelled();
                extSyms.next();
                importCount++;
            }

            int exportCount = 0;
            ghidra.program.model.address.AddressIterator epIter = symbolTable.getExternalEntryPointIterator();
            while (epIter.hasNext()) {
                session.monitor().checkCancelled();
                epIter.next();
                exportCount++;
            }

            int dataTypeCount = dtm.getDataTypeCount(false);

            int instructionCount = 0;
            InstructionIterator instrIter = listing.getInstructions(true);
            while (instrIter.hasNext()) {
                session.monitor().checkCancelled();
                instrIter.next();
                instructionCount++;
            }

            JsonObject stats = new JsonObject();
            stats.addProperty("functions", functionCount);
            stats.addProperty("symbols", symbolCount);
            stats.addProperty("strings", stringCount);
            stats.addProperty("imports", importCount);
            stats.addProperty("exports", exportCount);
            stats.addProperty("memory_size", memorySize);
            stats.addProperty("memory_blocks", memoryBlockCount);
            stats.addProperty("data_types", dataTypeCount);
            stats.addProperty("instructions", instructionCount);
            stats.addProperty("program_name", session.programName());
            stats.addProperty("executable_format", session.program().getExecutableFormat());
            String compiler = session.program().getCompiler();
            stats.addProperty("compiler", (compiler != null && !compiler.isEmpty()) ? compiler : "Unknown");

            JsonObject result = new JsonObject();
            result.add("stats", stats);
            return result;
        } catch (CancelledException e) {
            throw e;
        } catch (Exception e) {
            return errorResult("Failed to gather statistics: " + e.getMessage());
        }
    }
}
