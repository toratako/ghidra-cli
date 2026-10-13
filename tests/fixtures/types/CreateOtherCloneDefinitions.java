import ghidra.app.script.GhidraScript;
import ghidra.docking.settings.FormatSettingsDefinition;
import ghidra.program.model.data.*;

public class CreateOtherCloneDefinitions extends GhidraScript {
  public void run() throws Exception {
    var dtm = currentProgram.getDataTypeManager();
    var path = new CategoryPath("/Types");
    var values = new EnumDataType(path, "Values", 4, dtm);
    values.setDescription("enum description");
    values.add("FIRST", 1, "first comment");
    values.add("ALIAS", 1, "alias comment");
    var savedEnum = dtm.addDataType(values, null);
    FormatSettingsDefinition.DEF.setChoice(
        savedEnum.getDefaultSettings(), FormatSettingsDefinition.DECIMAL);
    var alias = new TypedefDataType(path, "Alias", savedEnum, dtm);
    var savedAlias = dtm.addDataType(alias, null);
    FormatSettingsDefinition.DEF.setChoice(
        savedAlias.getDefaultSettings(), FormatSettingsDefinition.BINARY);
    var ptr = new PointerTypedef("Relative", savedEnum, 8, dtm, 12L);
    var savedPointer = dtm.addDataType(ptr, null);
    savedPointer.setCategoryPath(path);
    FormatSettingsDefinition.DEF.setChoice(
        savedPointer.getDefaultSettings(), FormatSettingsDefinition.DECIMAL);
    var function = new FunctionDefinitionDataType(path, "Callback", dtm);
    function.setComment("callback comment");
    function.setReturnType(savedAlias);
    function.setArguments(new ParameterDefinitionImpl("arg", savedPointer, "argument comment"));
    function.setVarArgs(true);
    function.setNoReturn(true);
    function.setCallingConvention("__cdecl");
    dtm.addDataType(function, null);
  }
}
