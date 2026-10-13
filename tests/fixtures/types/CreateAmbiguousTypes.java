import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.StructureDataType;

public class CreateAmbiguousTypes extends GhidraScript {
  public void run() throws Exception {
    var dtm = currentProgram.getDataTypeManager();
    String[] paths = {"/zeta", "/", "/alpha"};
    for (int i = 0; i < paths.length; i++)
      dtm.addDataType(
          new StructureDataType(new CategoryPath(paths[i]), "Shared", i + 1, dtm), null);
  }
}
