import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import java.util.Arrays;
import java.util.Objects;

public class CheckSavedClonedDefinitions extends GhidraScript {
  public void run() throws Exception {
    var dtm = currentProgram.getDataTypeManager();
    for (String name : new String[] {"Node", "Packed", "Union", "PackedUnion"}) {
      var original = (Composite) dtm.getDataType("/Source/" + name);
      var copy = (Composite) dtm.getDataType("/Draft/" + name + "Copy");
      if (original.getUniversalID().equals(copy.getUniversalID())
          || original.getSourceArchive().getArchiveType() != ArchiveType.FILE
          || copy.getSourceArchive().getArchiveType() != ArchiveType.PROGRAM)
        throw new IllegalStateException("Identity or source archive was not preserved");
      if (original.getPackingType() != copy.getPackingType()
          || original.getExplicitPackingValue() != copy.getExplicitPackingValue()
          || original.getAlignmentType() != copy.getAlignmentType()
          || original.getExplicitMinimumAlignment() != copy.getExplicitMinimumAlignment())
        throw new IllegalStateException("Packing or alignment changed");
      var fields = original.getDefinedComponents();
      var copied = copy.getDefinedComponents();
      for (int i = 0; i < fields.length; i++) {
        var a = fields[i].getDefaultSettings();
        var b = copied[i].getDefaultSettings();
        if (!Arrays.equals(a.getNames(), b.getNames()))
          throw new IllegalStateException("Explicit component settings changed");
        for (String key : a.getNames()) {
          if (!Objects.equals(a.getValue(key), b.getValue(key)))
            throw new IllegalStateException("Component setting not saved: " + key);
        }
        var oldType = fields[i].getDataType();
        var newType = copied[i].getDataType();
        if (oldType instanceof BitFieldDataType) {
          oldType = ((BitFieldDataType) oldType).getBaseDataType();
          newType = ((BitFieldDataType) newType).getBaseDataType();
        }
        if (oldType != newType) throw new IllegalStateException("Dependency was copied");
      }
    }
    var original = (Structure) dtm.getDataType("/Source/Node");
    var copy = (Structure) dtm.getDataType("/Draft/NodeCopy");
    if (((Pointer) copy.getComponentAt(8).getDataType()).getDataType() != original)
      throw new IllegalStateException("Self reference was redirected to the clone");
    var payload = (Structure) dtm.getDataType("/Source/Payload");
    payload.getComponentAt(0).setFieldName("shared_edit");
    if (((Structure) original.getComponentAt(0).getDataType())
                .getComponentAt(0)
                .getFieldName()
                .equals("shared_edit")
            == false
        || ((Structure) copy.getComponentAt(0).getDataType())
                .getComponentAt(0)
                .getFieldName()
                .equals("shared_edit")
            == false) throw new IllegalStateException("Dependency edits were not shared");
    copy.getComponentAt(20).setFieldName("independent_edit");
    if (!original.getComponentAt(20).getFieldName().equals("tail"))
      throw new IllegalStateException("Clone edit modified source definition");
  }
}
