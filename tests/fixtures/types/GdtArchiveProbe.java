import com.google.gson.JsonObject;
import ghidra.app.script.GhidraScript;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.data.ProgramBasedDataTypeManager;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.nio.file.Files;
import java.nio.file.Path;

// Uses a separate saved Program so the enclosing script owns no probe transaction.
public class GdtArchiveProbe extends GhidraScript {
    private Program real;
    private Program selected;
    private Object session;
    private Object dispatcher;
    private Method execute;
    private boolean cancelImport;
    private boolean cancelExport;
    private boolean cancelledAfterResolve;
    private boolean cancelledBeforeReopen;
    private boolean failSaves;
    private int saveCalls;
    private int transactions;
    private final TaskMonitorAdapter requestMonitor = new TaskMonitorAdapter(true) {
        @Override
        public void checkCancelled() throws CancelledException {
            if (cancelExport) {
                for (StackTraceElement frame : Thread.currentThread().getStackTrace()) {
                    if (frame.getClassName().endsWith(".TypeArchiveCommands")
                            && frame.getMethodName().equals("open")) {
                        // Export opens its saved and closed staging archive before publication.
                        cancelledBeforeReopen = true;
                        cancel();
                        break;
                    }
                }
            }
            super.checkCancelled();
        }
    };

    @Override
    public void run() throws Exception {
        String mode = getScriptArgs()[0];
        Path source = Path.of(getScriptArgs()[1]);
        Path output = Path.of(getScriptArgs()[2]);
        var folder = state.getProject().getProjectData().getRootFolder().createFolder(getScriptArgs()[3]);
        DomainFile file = currentProgram.getDomainFile().copyTo(folder, monitor);
        Object owner = new Object();
        real = (Program) file.getDomainObject(owner, true, false, monitor);
        try {
            int tx = real.startTransaction("Saved baseline");
            try { real.getDataTypeManager().addDataType(new StructureDataType("GdtProbeSaved", 1), null); }
            finally { real.endTransaction(tx, true); }
            real.save("Saved baseline", TaskMonitor.DUMMY);
            configure();
            if (mode.equals("pending-save")) pendingSave(source, output);
            else if (mode.equals("cancel-import")) cancelledImport(source);
            else if (mode.equals("cancel-export")) cancelledExport(source, output);
            else throw new IllegalArgumentException(mode);
            println("gdt-probe-ok:" + mode);
        } finally {
            cancelImport = false;
            cancelExport = false;
            failSaves = false;
            requestMonitor.clearCancelled();
            try {
                if (session != null) {
                    Method close = session.getClass().getDeclaredMethod("closeProgram");
                    close.setAccessible(true);
                    close.invoke(session);
                }
            } finally { real.release(owner); }
        }
    }

    private void pendingSave(Path source, Path output) throws Exception {
        int tx = real.startTransaction("Unsaved prior edit");
        try { real.getDataTypeManager().addDataType(new StructureDataType("GdtProbePending", 4), null); }
        finally { real.endTransaction(tx, true); }
        failSaves = true;
        int previousTransactions = transactions;
        success(command("type_archive_list", file(source)));
        check(saveCalls == 0 && transactions == previousTransactions,
            "Archive listing transacted or saved the unrelated Program");
        check(real.isChanged(), "Archive listing lost pending edits");
        checkSaved(false, false);
        JsonObject failed = command("type_export_gdt", all(output));
        check("error".equals(failed.get("status").getAsString()), failed.toString());
        check(failed.getAsJsonObject("detail").get("save_failed").getAsBoolean(), failed.toString());
        check(saveCalls == 1, "Export retried the failed Program save");
        check(!Files.exists(output), "Export published before Program save succeeded");
        check(real.isChanged() && real.getDataTypeManager().getDataType("/GdtProbePending") != null,
            "Failed save lost pending edits");
        checkSaved(false, false);
        failSaves = false;
        success(command("program_save", new JsonObject()));
        checkSaved(true, false);
        success(command("type_export_gdt", all(output)));
        check(Files.isRegularFile(output), "Recovery did not export the saved Program");
    }

    private void cancelledImport(Path source) throws Exception {
        int count = real.getDataTypeManager().getDataTypeCount(true);
        int archives = real.getDataTypeManager().getSourceArchives().size();
        cancelImport = true;
        JsonObject failed = command("type_import_gdt", all(source));
        check(cancelledAfterResolve, "Cancellation did not follow a native type mutation: " + failed);
        check("error".equals(failed.get("status").getAsString()), failed.toString());
        JsonObject detail = failed.getAsJsonObject("detail");
        check(detail.get("rolled_back").getAsBoolean() && detail.get("cancelled").getAsBoolean(), failed.toString());
        check(real.getDataTypeManager().getDataTypeCount(true) == count,
            "Cancelled import retained types or wrappers");
        check(real.getDataTypeManager().getSourceArchives().size() == archives,
            "Cancelled import retained an archive association");
        check(real.getCurrentTransactionInfo() == null, "Cancelled import leaked a transaction");
        checkSaved(false, false);
        cancelImport = false;
        requestMonitor.clearCancelled();
        success(command("type_import_gdt", all(source)));
        checkSaved(false, true);
    }

    private void cancelledExport(Path source, Path output) throws Exception {
        success(command("type_import_gdt", all(source)));
        long modification = real.getModificationNumber();
        cancelExport = true;
        JsonObject failed = command("type_export_gdt", all(output));
        check(cancelledBeforeReopen, "Cancellation did not reach the saved staging archive: " + failed);
        check("error".equals(failed.get("status").getAsString()), failed.toString());
        check(failed.getAsJsonObject("detail").get("cancelled").getAsBoolean(), failed.toString());
        check(!Files.exists(output), "Cancelled export published its archive");
        try (var paths = Files.list(output.getParent())) {
            check(paths.noneMatch(path -> path.getFileName().toString().startsWith("ghidra-cli-gdt-")),
                "Cancelled export left staging files");
        }
        check(real.getModificationNumber() == modification && !real.isChanged(),
            "Cancelled export changed the Program");
        checkSaved(false, true);
        cancelExport = false;
        requestMonitor.clearCancelled();
        success(command("type_export_gdt", all(output)));
        check(Files.isRegularFile(output), "Export did not recover after cancellation");
    }

    private void checkSaved(boolean pending, boolean imported) throws Exception {
        Object reader = new Object();
        Program saved = (Program) real.getDomainFile().getReadOnlyDomainObject(
            reader, DomainFile.DEFAULT_VERSION, TaskMonitor.DUMMY);
        try {
            var dtm = saved.getDataTypeManager();
            check(dtm.getDataType("/GdtProbeSaved") != null, "Earlier saved edit was lost");
            check((dtm.getDataType("/GdtProbePending") != null) == pending, "Unexpected saved pending edit");
            boolean hasImported = false;
            var types = dtm.getAllDataTypes();
            while (types.hasNext()) hasImported |= types.next().getPathName().startsWith("/Gdt/");
            check(hasImported == imported, "Unexpected saved GDT types");
        } finally { saved.release(reader); }
    }

    private void configure() throws Exception {
        Class<?> caller = StackWalker.getInstance(StackWalker.Option.RETAIN_CLASS_REFERENCE)
            .walk(frames -> frames.map(StackWalker.StackFrame::getDeclaringClass)
                .filter(type -> type.getSimpleName().equals("ScriptCommands")
                    && type.getPackageName().equals("ghidracli.script"))
                .findFirst().orElseThrow());
        ClassLoader loader = caller.getClassLoader();
        String prefix = caller.getPackageName().substring(0, caller.getPackageName().lastIndexOf('.') + 1);
        ProgramBasedDataTypeManager manager = (ProgramBasedDataTypeManager) Proxy.newProxyInstance(
            ProgramBasedDataTypeManager.class.getClassLoader(),
            new Class<?>[] { ProgramBasedDataTypeManager.class }, (proxy, method, args) -> {
                Object result = invoke(method, real.getDataTypeManager(), args);
                if (method.getName().equals("addDataTypes") && cancelImport) {
                    check(real.getDataTypeManager().getDataType("/Gdt/Payload") != null,
                        "Resolve cancellation preceded the dependency edit");
                    cancelledAfterResolve = true;
                    requestMonitor.cancel();
                }
                return result;
            });
        selected = (Program) Proxy.newProxyInstance(Program.class.getClassLoader(),
            new Class<?>[] { Program.class }, (proxy, method, args) -> {
                if (method.getName().equals("getDataTypeManager")) return manager;
                if (method.getName().equals("startTransaction")) transactions++;
                if (method.getName().equals("save")) {
                    saveCalls++;
                    if (failSaves) throw new IOException("injected GDT export pre-save failure");
                }
                return invoke(method, real, args);
            });
        Class<?> accessClass = loader.loadClass(prefix + "session.ScriptAccess");
        Object access = Proxy.newProxyInstance(loader, new Class<?>[] { accessClass }, (proxy, method, args) -> {
            switch (method.getName()) {
                case "program": return selected;
                case "setProgram": selected = (Program) args[0]; return null;
                case "state": return state;
                case "monitor": return requestMonitor;
                case "logError": printerr((String) args[0]); return null;
                default: throw new UnsupportedOperationException(method.getName());
            }
        });
        Class<?> sessionClass = loader.loadClass(prefix + "session.ProgramSession");
        var sessionConstructor = sessionClass.getDeclaredConstructor(accessClass);
        sessionConstructor.setAccessible(true);
        session = sessionConstructor.newInstance(access);
        Class<?> dispatcherClass = loader.loadClass(prefix + "runtime.CommandDispatcher");
        var dispatcherConstructor = dispatcherClass.getDeclaredConstructor(sessionClass);
        dispatcherConstructor.setAccessible(true);
        dispatcher = dispatcherConstructor.newInstance(session);
        execute = dispatcherClass.getDeclaredMethod("execute", String.class, JsonObject.class);
        execute.setAccessible(true);
    }

    private JsonObject command(String name, JsonObject args) throws Exception {
        return (JsonObject) execute.invoke(dispatcher, name, args);
    }

    private static Object invoke(Method method, Object target, Object[] args) throws Throwable {
        try { return method.invoke(target, args); }
        catch (InvocationTargetException error) { throw error.getCause(); }
    }

    private static JsonObject file(Path path) {
        JsonObject args = new JsonObject();
        args.addProperty("file", path.toString());
        return args;
    }

    private static JsonObject all(Path path) {
        JsonObject args = file(path);
        args.addProperty("all", true);
        return args;
    }

    private static void success(JsonObject response) {
        check("success".equals(response.get("status").getAsString()), response.toString());
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new IllegalStateException(message);
    }
}
