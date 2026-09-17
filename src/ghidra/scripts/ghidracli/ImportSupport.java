package ghidracli;

import com.google.gson.JsonObject;
import generic.stl.Pair;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.AutoImporter;
import ghidra.app.util.importer.LcsHintLoadSpecChooser;
import ghidra.app.util.importer.LoadSpecChooser;
import ghidra.app.util.importer.LoaderArgsOptionChooser;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.LoadResults;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.Loader;
import ghidra.app.util.opinion.LoaderService;
import ghidra.formats.gfilesystem.FileSystemService;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.Project;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Program;
import ghidra.program.util.GhidraProgramUtilities;
import ghidra.util.task.TaskMonitor;
import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Predicate;
import static ghidracli.JsonProtocol.*;

/** Shared import/save boundary for the bridge and the short-lived headless script. */
public final class ImportSupport {
    private ImportSupport() {}

    @FunctionalInterface
    public interface Analysis { void run(Program program) throws Exception; }

    public static JsonObject run(Project project, JsonObject args, Object consumer,
            TaskMonitor monitor, Analysis analysis) throws Exception {
        File binary = new File(getArgString(args, "binary_path"));
        String requested = getArgString(args, "program");
        String name = requested == null ? binary.getName() : requested;
        if (name.isBlank() || name.equals(".") || name.equals("..")
                || name.contains("/") || name.contains("\\")) {
            throw new IllegalArgumentException("Import program name must be a single non-empty file name");
        }
        if (!binary.isFile()) throw new IllegalArgumentException("Binary file not found: " + binary);
        if (requested != null && project.getProjectData().getRootFolder().getFile(name) != null) {
            throw new IllegalArgumentException("Program already exists: " + name + "; choose another --program name");
        }
        String loader = getArgString(args, "loader");
        String language = getArgString(args, "language");
        String compiler = getArgString(args, "compiler_spec");
        if (compiler != null && language == null) {
            throw new IllegalArgumentException("--compiler-spec requires --language");
        }
        LoadSpecChooser chooser = language == null ? LoadSpecChooser.CHOOSE_THE_FIRST_PREFERRED
            : new LcsHintLoadSpecChooser(new LanguageID(language),
                compiler == null ? null : new CompilerSpecID(compiler));
        List<Pair<String, String>> options = new ArrayList<>();
        if (args.has("loader_options")) {
            for (var option : args.getAsJsonArray("loader_options")) {
                var pair = option.getAsJsonArray();
                String optionName = pair.get(0).getAsString();
                String value = pair.get(1).getAsString();
                if (optionName.equalsIgnoreCase("baseAddr") && !AddressCodec.isValidSyntax(value)) {
                    JsonObject detail = new JsonObject();
                    detail.addProperty("stage", "import.options");
                    detail.addProperty("import_status", "not_started");
                    detail.addProperty("option", "-loader-" + optionName);
                    throw new JsonProtocol.CommandException(
                        "Base address requires explicit 0x-prefixed hexadecimal components: " + value,
                        detail);
                }
                options.add(new Pair<>("-loader-" + optionName, value));
            }
        }
        Predicate<Loader> filter = candidate -> loader == null
            || candidate.getClass().getSimpleName().equals(loader)
            || candidate.getClass().getName().equals(loader);
        validateLoaderOptions(binary, filter, chooser, options, monitor);
        LoadResults<Program> loaded = AutoImporter.importFresh(binary, project, "/", consumer,
            new MessageLog(), monitor, filter,
            chooser, name, new LoaderArgsOptionChooser(options));
        if (loaded == null) throw new IllegalStateException("No loader accepted the binary");
        String analysisState = analysis == null ? "skipped" : "not_started";
        String stage = "import.analysis";
        try {
            if (analysis != null) {
                analysisState = "unknown";
                Program program = loaded.getPrimaryDomainObject();
                // This detached program belongs to the importer, not the live
                // ProgramSession. Close its owned transaction before saving it.
                ProgramTransaction transaction = new ProgramTransaction(program, "ghidra-cli import analysis");
                boolean completed = false;
                try {
                    ghidra.app.plugin.core.analysis.AutoAnalysisManager.getAnalysisManager(program)
                        .initializeOptions();
                    analysis.run(program);
                    monitor.checkCancelled();
                    GhidraProgramUtilities.markProgramAnalyzed(program);
                    completed = true;
                } finally {
                    transaction.end(completed);
                }
                analysisState = "completed";
            }
            stage = "import.save";
            loaded.save(monitor);
            DomainFile saved = loaded.getPrimary().getSavedDomainFile();
            if (saved == null) throw new IllegalStateException("Import did not save a project file");
            JsonObject result = new JsonObject();
            result.addProperty("status", "success");
            result.addProperty("program", saved.getName());
            result.addProperty("program_path", saved.getPathname());
            result.addProperty("import_status", "saved");
            result.addProperty("analysis_status", analysisState);
            return result;
        } catch (Exception error) {
            JsonObject detail = new JsonObject();
            detail.addProperty("stage", stage);
            detail.addProperty("analysis_status", analysisState);
            DomainFile saved = loaded.getPrimary().getSavedDomainFile();
            detail.addProperty("import_status", saved == null ? "unknown" : "saved");
            if (saved != null) detail.addProperty("program", saved.getPathname());
            throw new JsonProtocol.CommandException(stage + " failed: " + error.getMessage(), detail);
        } finally {
            loaded.release(consumer);
        }
    }

    public static JsonObject failure(Exception error) {
        return errorResponse(error.getMessage(), errorDetail(error));
    }

    private static void validateLoaderOptions(File binary, Predicate<Loader> filter,
            LoadSpecChooser chooser, List<Pair<String, String>> options, TaskMonitor monitor)
            throws Exception {
        if (options.isEmpty()) return;
        FileSystemService fs = FileSystemService.getInstance();
        try (ByteProvider provider = fs.getByteProvider(fs.getLocalFSRL(binary), true, monitor)) {
            LoadSpec spec = chooser.choose(LoaderService.getSupportedLoadSpecs(provider, filter));
            if (spec == null) throw new IllegalArgumentException("No loader accepted the binary");
            var defaults = spec.getLoader().getDefaultOptions(provider, spec, null, false, false);
            for (var requested : options) {
                var definition = defaults == null ? null : defaults.stream().filter(option ->
                    requested.first.equalsIgnoreCase(option.getArg())).findFirst().orElse(null);
                if (definition == null) {
                    JsonObject detail = new JsonObject();
                    detail.addProperty("stage", "import.options");
                    detail.addProperty("import_status", "not_started");
                    detail.addProperty("option", requested.first);
                    detail.addProperty("loader", spec.getLoader().getClass().getSimpleName());
                    throw new JsonProtocol.CommandException("Unsupported loader option "
                        + requested.first + " for " + spec.getLoader().getName(), detail);
                }
                if (requested.first.equalsIgnoreCase("-loader-baseAddr")) {
                    try {
                        var language = spec.getLanguageCompilerSpec();
                        var factory = language == null ? null : language.getLanguage().getAddressFactory();
                        Address address = AddressCodec.parse(factory, requested.second);
                        if (address == null) throw new IllegalArgumentException("No address space is available");
                        // AutoImporter on Ghidra 12 forwards only OptionChooser.getArgs(),
                        // so a choose() override cannot enforce the codec. Check the native
                        // interpretation before loading anything, including truncation in
                        // segmented spaces and sign recovery in narrower flat spaces.
                        var nativeOption = definition.copy();
                        if (!nativeOption.parseAndSetValueByType(requested.second, factory)
                                || !address.equals(nativeOption.getValue())) {
                            throw new IllegalArgumentException("Loader cannot preserve the requested address");
                        }
                    } catch (IllegalArgumentException error) {
                        JsonObject detail = new JsonObject();
                        detail.addProperty("stage", "import.options");
                        detail.addProperty("import_status", "not_started");
                        detail.addProperty("option", requested.first);
                        throw new JsonProtocol.CommandException("Invalid base address " + requested.second
                            + ": " + error.getMessage(), detail);
                    }
                }
            }
        }
    }
}
