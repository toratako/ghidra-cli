import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.Complex8DataType;
import ghidra.program.model.data.FileDataTypeManager;
import ghidra.program.model.data.StringDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.Unicode32DataType;
import ghidra.program.model.data.UnicodeDataType;
import java.io.File;

public class GdtEndianArchiveFixture extends GhidraScript {
  @Override
  public void run() throws Exception {
    try (var archive =
        FileDataTypeManager.createFileArchive(
            new File(getScriptArgs()[0]),
            currentProgram.getLanguageID(),
            currentProgram.getCompilerSpec().getCompilerSpecID())) {
      int transaction = archive.startTransaction("Create endian-dependent archive fixture");
      boolean commit = false;
      try {
        var holder = new StructureDataType(new CategoryPath("/Gdt"), "ComplexValue", 0, archive);
        holder.add(new Complex8DataType(archive), "value", null);
        archive.addDataType(holder, null);
        for (var text :
            new ghidra.program.model.data.DataType[] {
              new UnicodeDataType(archive),
              new Unicode32DataType(archive),
              new StringDataType(archive)
            }) {
          var string =
              new StructureDataType(new CategoryPath("/Gdt"), text.getName() + "Value", 0, archive);
          string.add(text, 8, "value", null);
          archive.addDataType(string, null);
        }
        commit = true;
      } finally {
        archive.endTransaction(transaction, commit);
      }
      archive.save();
    }
  }
}
