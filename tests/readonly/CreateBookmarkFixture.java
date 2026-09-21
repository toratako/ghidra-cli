import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;

public class CreateBookmarkFixture extends GhidraScript {
    public void run() throws Exception {
        var language = DefaultLanguageService.getLanguageService()
            .getLanguage(new LanguageID("x86:LE:64:default"));
        var program = new ProgramDB(getScriptArgs()[0], language,
            language.getDefaultCompilerSpec(), this);
        try {
            int tx = program.startTransaction("bookmark fixture");
            try {
                var space = program.getAddressFactory().getDefaultAddressSpace();
                var entry = space.getAddress(0x1000);
                program.getMemory().createInitializedBlock("code", entry,
                    0x100, (byte) 0, monitor, false);
                program.getFunctionManager().createFunction("bookmark_target", entry,
                    new AddressSet(entry, entry.add(0x3f)), SourceType.USER_DEFINED);
                var bookmarks = program.getBookmarkManager();
                bookmarks.setBookmark(entry, BookmarkType.ERROR, "Disassembler",
                    "Unable to resolve instruction flow");
                bookmarks.setBookmark(entry, BookmarkType.NOTE, "Disassembler",
                    "User note: inspect the jump table");
                bookmarks.setBookmark(entry, BookmarkType.NOTE, "Review",
                    "User note: 東京");
                bookmarks.setBookmark(entry.add(0x10), BookmarkType.ERROR, "Analysis",
                    "Conflicting data definition");
                bookmarks.setBookmark(space.getAddress(0x9000), BookmarkType.NOTE, "Unmapped",
                    "User note outside mapped memory");
                var external = program.getExternalManager().addExtFunction("bookmarks", "outside",
                    null, SourceType.USER_DEFINED).getExternalSpaceAddress();
                bookmarks.setBookmark(external, BookmarkType.NOTE, "External",
                    "User note on an imported function");
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
