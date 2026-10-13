import com.google.gson.JsonObject;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import java.util.ArrayList;

public class SignatureCallbackFixture extends GhidraScript {
    public void run() throws Exception {
        var manager = currentProgram.getDataTypeManager();
        String mode = getScriptArgs()[0];
        if (mode.equals("create")) {
            var profile = (Structure) manager.addDataType(new StructureDataType(
                new CategoryPath("/Recovered"), "Profile", 24, manager), null);
            profile.replaceAtOffset(0, IntegerDataType.dataType, 4, "id", null);
            profile.replaceAtOffset(8, new PointerDataType(profile, manager),
                currentProgram.getDefaultPointerSize(), "next", "recursive link");
            profile.replaceAtOffset(20, ByteDataType.dataType, 1, "marker", null);
            var callback = new FunctionDefinitionDataType(
                new CategoryPath("/Callbacks"), "ProfileCmp", manager);
            callback.setReturnType(IntegerDataType.dataType);
            callback.setArguments(new ParameterDefinition[] {
                new ParameterDefinitionImpl("left", new PointerDataType(profile, manager), null),
                new ParameterDefinitionImpl("right", new PointerDataType(profile, manager), null)
            });
            var registered = manager.addDataType(callback, null);
            manager.addDataType(new TypedefDataType(new CategoryPath("/Recovered"),
                "ProfileCmp", new PointerDataType(registered, manager), manager), null);
        }

        var profile = (Structure) manager.getDataType("/Recovered/Profile");
        var callback = (FunctionDefinition) manager.getDataType("/Callbacks/ProfileCmp");
        var alias = (TypeDef) manager.getDataType("/Recovered/ProfileCmp");
        check(profile.getLength() == 24 && profile.getComponentAt(0).getFieldName().equals("id")
            && profile.getComponentAt(8).getFieldName().equals("next")
            && profile.getComponentAt(20).getFieldName().equals("marker"),
            "Existing padded structure layout changed");
        check(pointer(profile.getComponentAt(8).getDataType()).equals(profile),
            "Recursive structure identity changed");
        check(pointer(alias.getDataType()).equals(callback), "Typedef target changed");
        checkComparison(callback, profile);

        if (!mode.equals("create")) {
            var function = getFunctionAt(toAddr(0x1000));
            check(pointer(function.getParameter(0).getDataType()).equals(profile),
                "Function parameter points at a copied Profile");
            if (mode.equals("bound")) {
                check(function.getReturnType() instanceof VoidDataType, "Void return changed");
                check(function.getParameterCount() == 2, "Wrong bound parameter count");
                check(function.getParameter(1).getDataType().equals(alias),
                    "Bound typedef identity changed");
            } else if (mode.equals("direct")) {
                check(function.getReturnType() instanceof VoidDataType, "Void return changed");
                check(function.getParameterCount() == 2, "Wrong direct parameter count");
                checkComparison((FunctionDefinition) pointer(function.getParameter(1).getDataType()), profile);
            } else if (mode.equals("nested")) {
                check(function.getReturnType() instanceof VoidDataType, "Void return changed");
                var outer = (FunctionDefinition) pointer(function.getParameter(1).getDataType());
                check(outer.getArguments().length == 2, "Nested callback lost parameters");
                check(pointer(outer.getArguments()[0].getDataType()).equals(profile),
                    "Nested callback changed Profile identity");
                var inner = (FunctionDefinition) pointer(outer.getArguments()[1].getDataType());
                check(inner.getReturnType().getName().equals("int") && inner.getArguments().length == 1,
                    "Nested predicate has the wrong signature");
                check(pointer(inner.getArguments()[0].getDataType()).equals(profile),
                    "Nested predicate changed Profile identity");
            } else throw new IllegalArgumentException("Unknown mode: " + mode);

            for (String name : new String[] { "ChosenProfileCmp", "SelectedProfile", "lookup" }) {
                var matches = new ArrayList<DataType>();
                manager.findDataTypes(name, matches);
                check(matches.isEmpty(), "Temporary parser declaration persisted: " + name);
            }
        }

        var identities = new JsonObject();
        for (DataType type : new DataType[] { profile, callback, alias })
            identities.addProperty(type.getPathName(), type.getUniversalID().toString());
        println(identities.toString());
    }

    private DataType pointer(DataType type) {
        check(type instanceof Pointer && type.getLength() == currentProgram.getDefaultPointerSize(),
            "Wrong pointer type or target width: " + type);
        return ((Pointer) type).getDataType();
    }

    private void checkComparison(FunctionDefinition callback, DataType profile) {
        check(callback.getReturnType().getName().equals("int") && callback.getArguments().length == 2,
            "Comparison callback has the wrong signature");
        for (var parameter : callback.getArguments())
            check(pointer(parameter.getDataType()).equals(profile), "Callback Profile identity changed");
    }

    private void check(boolean condition, String message) {
        if (!condition) throw new IllegalStateException(message);
    }
}
