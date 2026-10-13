import ghidra.app.script.GhidraScript;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;

public class CheckAutoSavedComment extends GhidraScript {
  public void run() throws Exception {
    if (currentProgram.isChanged()) throw new IllegalStateException("Program is still dirty");
    Object consumer = new Object();
    Program saved =
        (Program)
            currentProgram
                .getDomainFile()
                .getReadOnlyDomainObject(consumer, DomainFile.DEFAULT_VERSION, monitor);
    try {
      String actual =
          saved
              .getListing()
              .getComment(
                  CodeUnit.EOL_COMMENT, saved.getAddressFactory().getAddress(getScriptArgs()[0]));
      if (!getScriptArgs()[1].equals(actual)) {
        throw new IllegalStateException("Saved comment differs: " + actual);
      }
    } finally {
      saved.release(consumer);
    }
  }
}
