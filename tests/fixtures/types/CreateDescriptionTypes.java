
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
public class CreateDescriptionTypes extends GhidraScript {
    public void run() throws Exception {
        var dtm = currentProgram.getDataTypeManager();
        var path = new CategoryPath("/Descriptions");
        var node = new StructureDataType(path, "Node", 8, dtm);
        node.replaceAtOffset(0, DWordDataType.dataType, 4, "value", "field comment");
        node.setDescription("original node");
        var savedNode = dtm.addDataType(node, null);
        var choice = new UnionDataType(path, "Choice", dtm);
        choice.add(savedNode, "node", "nested type");
        choice.add(new PointerDataType(savedNode, dtm), "link", "shared target");
        choice.setDescription("original union");
        var savedChoice = dtm.addDataType(choice, null);
        var mode = new EnumDataType(path, "Mode", 4, dtm);
        mode.add("Read", 1, "member comment");
        mode.add("Write", 2);
        mode.setDescription("original enum");
        var savedMode = dtm.addDataType(mode, null);
        var holder = new StructureDataType(path, "Holder", 0, dtm);
        holder.add(new PointerDataType(savedNode, dtm), "link", "pointer");
        holder.add(new ArrayDataType(savedNode, 2, -1, dtm), "nodes", "array");
        holder.add(savedChoice, "choice", "union");
        holder.add(savedMode, "mode", "enum");
        var savedHolder = dtm.addDataType(holder, null);
        var address = toAddr(0x1000);
        currentProgram.getMemory().createUninitializedBlock("data", address, 256, false);
        currentProgram.getListing().createData(address, savedHolder);
        dtm.addDataType(new TypedefDataType(path, "Alias", savedNode, dtm), null);
        dtm.addDataType(new FunctionDefinitionDataType(path, "Callback", dtm), null);
        var other = new StructureDataType(new CategoryPath("/Other"), "Node", 4, dtm);
        other.setDescription("other node");
        dtm.addDataType(other, null);
    }
}
