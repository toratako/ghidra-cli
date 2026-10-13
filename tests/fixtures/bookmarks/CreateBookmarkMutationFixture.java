import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;

public class CreateBookmarkMutationFixture extends GhidraScript {
    public void run() throws Exception {
        var language = DefaultLanguageService.getLanguageService()
            .getLanguage(new LanguageID("x86:LE:64:default"));
        var program = new ProgramDB(getScriptArgs()[0], language,
            language.getDefaultCompilerSpec(), this);
        try {
            int tx = program.startTransaction("bookmark mutation fixture");
            try {
                var entry = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000);
                program.getMemory().createInitializedBlock("code", entry,
                    0x100, (byte) 0, monitor, false);
                program.getFunctionManager().createFunction("bookmark_target", entry,
                    new AddressSet(entry, entry.add(0x3f)), SourceType.USER_DEFINED);
                var bookmarks = program.getBookmarkManager();
                bookmarks.setBookmark(entry, BookmarkType.ERROR, "Disassembler", "Analysis error");
                bookmarks.setBookmark(entry, BookmarkType.NOTE, "Disassembler", "Review this error");
                bookmarks.setBookmark(entry, BookmarkType.NOTE, "Review", "Original review");
                program.getExternalManager().addExtFunction("bookmarks", "bookmark_external",
                    null, SourceType.USER_DEFINED);
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
