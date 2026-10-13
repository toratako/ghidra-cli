import ghidra.app.script.GhidraScript;
import ghidra.docking.settings.FormatSettingsDefinition;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.data.EndianSettingsDefinition;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.Program;

public class CheckSavedFieldSettings extends GhidraScript {
  public void run() throws Exception {
    Object consumer = new Object();
    Program saved =
        (Program)
            currentProgram
                .getDomainFile()
                .getReadOnlyDomainObject(consumer, DomainFile.DEFAULT_VERSION, monitor);
    try {
      String[] args = getScriptArgs();
      var structure = (Structure) saved.getDataTypeManager().getDataType("/" + args[0]);
      for (int i = 1; i < args.length; i++) {
        var settings = structure.getComponentAt(Integer.parseInt(args[i])).getDefaultSettings();
        if (FormatSettingsDefinition.DEF.getChoice(settings) != FormatSettingsDefinition.DECIMAL)
          throw new IllegalStateException("Lost field format at " + args[i]);
        if (EndianSettingsDefinition.DEF.getChoice(settings) != EndianSettingsDefinition.BIG)
          throw new IllegalStateException("Lost field byte order at " + args[i]);
      }
    } finally {
      saved.release(consumer);
    }
  }
}
