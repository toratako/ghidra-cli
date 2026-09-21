import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;

public class CreateXrefMetadataFixture extends GhidraScript {
    public void run() throws Exception {
        var language = DefaultLanguageService.getLanguageService()
            .getLanguage(new LanguageID("x86:LE:32:default"));
        var program = new ProgramDB(getScriptArgs()[0], language,
            language.getDefaultCompilerSpec(), this);
        try {
            int tx = program.startTransaction("xref metadata fixture");
            try {
                var space = program.getAddressFactory().getDefaultAddressSpace();
                var site = space.getAddress(0x1000);
                var target = space.getAddress(0x2000);
                program.getMemory().createInitializedBlock("code", site,
                    0x20, (byte) 0, monitor, false);
                program.getMemory().createInitializedBlock("target", target,
                    0x20, (byte) 0, monitor, false);
                // ENTER has two explicit operands; retain a third mnemonic reference too.
                program.getMemory().setBytes(site, new byte[] {(byte) 0xc8, 8, 0, 8});
                var body = new AddressSet(site, site.add(3));
                if (!new DisassembleCommand(site, body, false).applyTo(program, monitor)) {
                    throw new IllegalStateException("Could not disassemble xref fixture");
                }
                program.getFunctionManager().createFunction("xref_source", site, body,
                    SourceType.USER_DEFINED);
                program.getFunctionManager().createFunction("xref_target", target,
                    new AddressSet(target), SourceType.USER_DEFINED);
                var references = program.getReferenceManager();
                references.removeAllReferencesFrom(site);
                references.addMemoryReference(site, target, RefType.DATA, SourceType.IMPORTED, -1);
                var secondary = references.addMemoryReference(site, target, RefType.DATA,
                    SourceType.USER_DEFINED, 0);
                references.setPrimary(secondary, false);
                references.addMemoryReference(site, target, RefType.DATA, SourceType.ANALYSIS, 1);
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
