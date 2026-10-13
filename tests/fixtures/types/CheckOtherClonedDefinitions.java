import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import java.util.Objects;

public class CheckOtherClonedDefinitions extends GhidraScript {
  public void run() throws Exception {
    var dtm = currentProgram.getDataTypeManager();
    for (String name : new String[] {"Values", "Alias", "Relative", "Callback"}) {
      var source = dtm.getDataType("/Types/" + name);
      var copy = dtm.getDataType("/Types/" + name + "Copy");
      if (source.getUniversalID().equals(copy.getUniversalID()))
        throw new IllegalStateException("Clone identity matches source");
      for (String key : source.getDefaultSettings().getNames()) {
        if (!Objects.equals(
            source.getDefaultSettings().getValue(key), copy.getDefaultSettings().getValue(key)))
          throw new IllegalStateException("Default setting lost: " + name + " " + key);
      }
      if (source instanceof TypeDef
          && ((TypeDef) source).getDataType() != ((TypeDef) copy).getDataType())
        throw new IllegalStateException("Typedef dependency changed");
    }
    var sourceEnum = (ghidra.program.model.data.Enum) dtm.getDataType("/Types/Values");
    var enumCopy = (ghidra.program.model.data.Enum) dtm.getDataType("/Types/ValuesCopy");
    for (String name : sourceEnum.getNames()) {
      if (sourceEnum.getValue(name) != enumCopy.getValue(name)
          || !Objects.equals(sourceEnum.getComment(name), enumCopy.getComment(name)))
        throw new IllegalStateException("Enum member changed");
    }
    var original = (FunctionDefinition) dtm.getDataType("/Types/Callback");
    var copy = (FunctionDefinition) dtm.getDataType("/Types/CallbackCopy");
    if (original.getReturnType() != copy.getReturnType()
        || !copy.hasVarArgs()
        || !copy.hasNoReturn()
        || !Objects.equals(original.getComment(), copy.getComment())
        || !Objects.equals(original.getCallingConventionName(), copy.getCallingConventionName()))
      throw new IllegalStateException("Function properties changed");
    var originalArg = original.getArguments()[0];
    var copiedArg = copy.getArguments()[0];
    if (originalArg.getDataType() != copiedArg.getDataType()
        || !Objects.equals(originalArg.getName(), copiedArg.getName())
        || !Objects.equals(originalArg.getComment(), copiedArg.getComment()))
      throw new IllegalStateException("Function argument changed");
  }
}
