import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;

public class CreateFunctionDetailsFixture extends GhidraScript {
    public void run() throws Exception {
        var language = DefaultLanguageService.getLanguageService()
            .getLanguage(new LanguageID("x86:LE:32:default"));
        var program = new ProgramDB(getScriptArgs()[0], language,
            language.getCompilerSpecByID(new CompilerSpecID(getScriptArgs()[1])), this);
        try {
            int tx = program.startTransaction("function details fixture");
            try {
                var space = program.getAddressFactory().getDefaultAddressSpace();
                program.getMemory().createInitializedBlock("code", space.getAddress(0xf00),
                    0x300, (byte) 0xc3, monitor, false);
                var body = new AddressSet(space.getAddress(0xff0), space.getAddress(0xff1));
                body.add(space.getAddress(0x1000), space.getAddress(0x1004));
                body.add(space.getAddress(0x1100), space.getAddress(0x1102));
                var functions = program.getFunctionManager();
                functions.createFunction("disjoint", space.getAddress(0x1000), body,
                    SourceType.USER_DEFINED);

                var overlay = program.getMemory().createInitializedBlock("body_overlay",
                    space.getAddress(0x1000), 0x20, (byte) 0xc3, monitor, true);
                var overlayBody = new AddressSet(overlay.getStart(), overlay.getStart().add(1));
                overlayBody.add(overlay.getStart().add(0x10));
                functions.createFunction("overlay_body", overlay.getStart(), overlayBody,
                    SourceType.USER_DEFINED);
                var unmapped = space.getAddress(0x9000);
                functions.createFunction("unmapped_body", unmapped, new AddressSet(unmapped),
                    SourceType.USER_DEFINED);
                program.getExternalManager().addExtFunction("library", "outside_body", null,
                    SourceType.USER_DEFINED);
            } finally {
                program.endTransaction(tx, true);
            }
            state.getProject().getProjectData().getRootFolder()
                .createFile(getScriptArgs()[0], program, monitor);
        } finally {
            program.release(this);
        }
    }
}
