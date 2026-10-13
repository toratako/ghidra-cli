import ghidra.app.script.GhidraScript;
import ghidra.docking.settings.FormatSettingsDefinition;
import ghidra.program.model.data.*;

public class CreateResizePropagation extends GhidraScript {
  public void run() throws Exception {
    var dtm = currentProgram.getDataTypeManager();
    var child = new StructureDataType(CategoryPath.ROOT, "Child", 4, dtm);
    child.replaceAtOffset(0, WordDataType.dataType, 2, "value", "keep");
    var saved = dtm.addDataType(child, null);
    var alias = dtm.addDataType(new TypedefDataType("ChildAlias", saved), null);
    var array = dtm.addDataType(new ArrayDataType(alias, 3, 4), null);
    var holder = new StructureDataType(CategoryPath.ROOT, "Holder", 40, dtm);
    holder.replaceAtOffset(0, alias, 4, "child", null);
    holder.replaceAtOffset(8, array, 12, "array", null);
    holder.replaceAtOffset(36, DWordDataType.dataType, 4, "tail", "keep tail");
    var registeredHolder = dtm.addDataType(holder, null);
    var packed = new StructureDataType(CategoryPath.ROOT, "PackedHolder", 0, dtm);
    packed.setPackingEnabled(true);
    packed.add(saved, "child", null);
    packed.add(ByteDataType.dataType, "tag", "moves with packing");
    var registeredPacked = dtm.addDataType(packed, null);
    var union = new UnionDataType("UnionHolder");
    union.add(saved, "child", null);
    union.add(QWordDataType.dataType, "wide", null);
    dtm.addDataType(union, null);
    var nested = dtm.addDataType(new ArrayDataType(new ArrayDataType(alias, 2, 4), 2, 8), null);
    var address = toAddr(0x1000);
    currentProgram
        .getMemory()
        .createInitializedBlock("data", address, 512, (byte) 0, monitor, false);
    var listing = currentProgram.getListing();
    listing.createData(address, registeredHolder);
    listing.createData(toAddr(0x1080), registeredPacked);
    listing.createData(toAddr(0x1100), nested);
    listing.createData(toAddr(0x1180), alias);
    FormatSettingsDefinition.DEF.setChoice(
        listing.getDefinedDataAt(toAddr(0x1180)).getComponent(0), FormatSettingsDefinition.DECIMAL);
    FormatSettingsDefinition.DEF.setChoice(
        ((Structure) registeredHolder).getComponentAt(36).getDefaultSettings(),
        FormatSettingsDefinition.BINARY);
    var aligned = new StructureDataType(CategoryPath.ROOT, "Aligned", 4, dtm);
    aligned.setExplicitMinimumAlignment(8);
    aligned.replaceAtOffset(0, WordDataType.dataType, 2, "value", null);
    var registeredAligned = dtm.addDataType(aligned, null);
    dtm.addDataType(
        new TypedefDataType("AlignedArray", new ArrayDataType(registeredAligned, 2, 8)), null);
  }
}
