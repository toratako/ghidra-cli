import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;

public class CheckImportCategory extends GhidraScript {
    public void run() throws Exception {
        var dtm = currentProgram.getDataTypeManager();
        var root = (Structure) dtm.getDataType("/Item");
        if (getScriptArgs()[0].equals("setup")) {
            var address = toAddr(0x1000);
            currentProgram.getMemory().createInitializedBlock(
                "data", address, 64, (byte) 0, monitor, false);
            currentProgram.getListing().createData(address, root);
            currentProgram.getListing().createData(toAddr(0x1020), dtm.getDataType("/Holder"));
            return;
        }

        String category = getScriptArgs()[0];
        String field = getScriptArgs()[1];
        int size = Integer.parseInt(getScriptArgs()[2]);
        var imported = (Structure) dtm.getDataType(category + "/Item");
        if (root == null || root.getLength() != 8
                || !root.getComponent(0).getFieldName().equals("original"))
            throw new IllegalStateException("Root definition changed");
        var rootNested = (Structure) root.getComponent(1).getDataType();
        if (rootNested.getLength() != 4 || !rootNested.getCategoryPath().isRoot())
            throw new IllegalStateException("Root anonymous definition changed");
        if (imported == null || imported.getLength() != size
                || !imported.getComponent(0).getFieldName().equals(field)
                || imported.getUniversalID().equals(root.getUniversalID()))
            throw new IllegalStateException("Imported definition is not independent");
        var nested = (Structure) imported.getComponent(1).getDataType();
        if (nested.getLength() != size / 2
                || !nested.getCategoryPath().getPath().equals(category)
                || nested.getUniversalID().equals(rootNested.getUniversalID()))
            throw new IllegalStateException("Imported anonymous definition was not isolated");

        for (String path : new String[] { "", category }) {
            var item = dtm.getDataType(path + "/Item");
            var alias = (TypeDef) dtm.getDataType(path + "/ItemAlias");
            var holder = (Structure) dtm.getDataType(path + "/Holder");
            if (!alias.getDataType().equals(item) || !holder.getComponent(0).getDataType().equals(item))
                throw new IllegalStateException("Dependency resolved outside " + path);
            var callback = (TypeDef) dtm.getDataType(path + "/Callback");
            var function = (FunctionDefinition) ((Pointer) callback.getDataType()).getDataType();
            var parameter = (Pointer) function.getArguments()[0].getDataType();
            if (!parameter.getDataType().equals(item))
                throw new IllegalStateException("Callback parameter resolved outside " + path);
        }
        var link = (Structure) dtm.getDataType(category + "/Link");
        if (!((Pointer) link.getComponent(0).getDataType()).getDataType().equals(link)
                || !link.getComponent(1).getDataType().equals(dtm.getDataType("/Scalar"))
                || !link.getComponent(2).getDataType().equals(imported))
            throw new IllegalStateException("Recursive or existing dependency changed");
        var existingAlias = (TypeDef) dtm.getDataType("/ExistingAlias");
        var importedAlias = (TypeDef) dtm.getDataType(category + "/ImportedAlias");
        if (!existingAlias.getDataType().equals(root)
                || !importedAlias.getDataType().equals(existingAlias))
            throw new IllegalStateException("Existing alias was redirected to the imported definition");
        var data = currentProgram.getListing().getDefinedDataAt(toAddr(0x1000));
        var holderData = currentProgram.getListing().getDefinedDataAt(toAddr(0x1020));
        if (data == null || data.getLength() != 8 || !data.getDataType().equals(root)
                || holderData == null || holderData.getLength() != 8
                || !holderData.getComponent(0).getDataType().equals(root))
            throw new IllegalStateException("Existing applied data changed");
    }
}
