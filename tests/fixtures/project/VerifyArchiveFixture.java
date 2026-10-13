import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.DataTypeArchive;

public class VerifyArchiveFixture extends GhidraScript {
    public void run() throws Exception {
        if (!"GAR retained comment".equals(currentProgram.getListing().getComment(
                CodeUnit.EOL_COMMENT, currentProgram.getMinAddress()))) throw new AssertionError("comment");
        if (currentProgram.getOptions("Analysis").getBoolean("ASCII Strings", true)) throw new AssertionError("analysis option");
        if (currentProgram.getDataTypeManager().getDataType("/ProgramType") == null) throw new AssertionError("program type");
        var project = state.getProject().getProjectData();
        if (project.getFolder("/nested/inside/empty") == null) throw new AssertionError("empty folder");
        Object consumer = new Object();
        var file = project.getFile("/nested/inside/types.gdt");
        var archive = (DataTypeArchive) file.getReadOnlyDomainObject(consumer, -1, monitor);
        try {
            var type = archive.getDataTypeManager().getDataType("/ArchivedType");
            if (type == null || type.getLength() != 4) throw new AssertionError("archive type");
        } finally { archive.release(consumer); }
        var second = project.getFile("/nested/inside/second").getReadOnlyDomainObject(consumer, -1, monitor);
        second.release(consumer);
        println("verified");
    }
}
