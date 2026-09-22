import ghidra.app.script.GhidraScript;
import ghidra.program.database.DataTypeArchiveDB;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.CodeUnit;

public class CreateArchiveFixture extends GhidraScript {
    public void run() throws Exception {
        var root = state.getProject().getProjectData().getRootFolder();
        var nested = root.createFolder("nested").createFolder("inside");
        nested.createFolder("empty");
        currentProgram.getDomainFile().copyTo(nested, monitor).setName("second");
        Object consumer = new Object();
        var archive = new DataTypeArchiveDB(nested, "types.gdt", consumer);
        try {
            int tx = archive.startTransaction("archive fixture type");
            try {
                var type = new StructureDataType("ArchivedType", 0);
                type.add(DWordDataType.dataType, "member", "retained annotation");
                archive.getDataTypeManager().addDataType(type, DataTypeConflictHandler.DEFAULT_HANDLER);
            } finally { archive.endTransaction(tx, true); }
            archive.save("fixture", monitor);
        } finally { archive.release(consumer); }
        currentProgram.getListing().setComment(currentProgram.getMinAddress(), CodeUnit.EOL_COMMENT,
            "GAR retained comment");
        currentProgram.getOptions("Analysis").setBoolean("ASCII Strings", false);
        currentProgram.getDataTypeManager().addDataType(new StructureDataType("ProgramType", 8),
            DataTypeConflictHandler.DEFAULT_HANDLER);
    }
}
