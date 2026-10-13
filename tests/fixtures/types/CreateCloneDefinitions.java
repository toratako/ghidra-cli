import ghidra.app.script.GhidraScript;
import ghidra.docking.settings.FormatSettingsDefinition;
import ghidra.program.model.data.*;
import java.io.File;

public class CreateCloneDefinitions extends GhidraScript {
  public void run() throws Exception {
    var archive =
        FileDataTypeManager.createFileArchive(
            new File(getScriptArgs()[0]),
            currentProgram.getLanguageID(),
            currentProgram.getCompilerSpec().getCompilerSpecID());
    try {
      int tx = archive.startTransaction("Fixture definitions");
      try {
        var path = new CategoryPath("/Source");
        var payload =
            (Structure)
                archive.addDataType(new StructureDataType(path, "Payload", 4, archive), null);
        payload.replaceAtOffset(0, DWordDataType.dataType, 4, "value", "shared payload");
        var node =
            (Structure) archive.addDataType(new StructureDataType(path, "Node", 24, archive), null);
        node.setDescription("recovered node");
        node.replaceAtOffset(0, payload, 4, "payload", "shared definition");
        node.replaceAtOffset(
            8, new PointerDataType(node, archive), 8, "next", "original self reference");
        node.insertBitFieldAt(16, 1, 0, UnsignedIntegerDataType.dataType, 3, "mode", "mode bits");
        node.insertBitFieldAt(16, 1, 3, UnsignedIntegerDataType.dataType, 2, null, "unnamed bits");
        node.replaceAtOffset(20, DWordDataType.dataType, 4, "tail", "tail comment");
        for (boolean packed : new boolean[] {false, true}) {
          String name = packed ? "PackedUnion" : "Union";
          var union = new UnionDataType(path, name, archive);
          union.setDescription("union description");
          if (packed) {
            union.setExplicitPackingValue(2);
            union.setExplicitMinimumAlignment(16);
          }
          union.add(payload, "payload", "shared union dependency");
          union.add(QWordDataType.dataType, null, "unnamed member");
          union.addBitField(UnsignedIntegerDataType.dataType, 3, "flags", "union bits");
          archive.addDataType(union, null);
        }
        var packed = new StructureDataType(path, "Packed", 0, archive);
        packed.setDescription("packed description");
        packed.setExplicitPackingValue(2);
        packed.setExplicitMinimumAlignment(16);
        packed.add(ByteDataType.dataType, "tag", "tag comment");
        packed.add(payload, "payload", "shared packed dependency");
        packed.addBitField(UnsignedIntegerDataType.dataType, 3, "flags", "packed bits");
        archive.addDataType(packed, null);
      } finally {
        archive.endTransaction(tx, true);
      }
      archive.save();
      var dtm = currentProgram.getDataTypeManager();
      for (String name : new String[] {"Node", "Packed", "Union", "PackedUnion"}) {
        var registered = (Composite) dtm.addDataType(archive.getDataType("/Source/" + name), null);
        for (var field : registered.getDefinedComponents()) {
          if (field.getDataType().getSettingsDefinitions().length == 0) continue;
          FormatSettingsDefinition.DEF.setChoice(
              field.getDefaultSettings(), FormatSettingsDefinition.DECIMAL);
          EndianSettingsDefinition.DEF.setChoice(
              field.getDefaultSettings(), EndianSettingsDefinition.BIG);
        }
      }
    } finally {
      archive.close();
    }
  }
}
