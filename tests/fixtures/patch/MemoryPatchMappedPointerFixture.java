import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.symbol.SourceType;

public class MemoryPatchMappedPointerFixture extends GhidraScript {
  public void run() throws Exception {
    var memory = currentProgram.getMemory();
    var listing = currentProgram.getListing();
    var start = toAddr(0x7000);
    switch (getScriptArgs()[0]) {
      case "create":
        memory.createInitializedBlock("pointer_prefix", start, 1, (byte) 0, monitor, false);
        memory.createByteMappedBlock(
            "pointer_tail", toAddr(0x7001), toAddr(0x7002), 16 * 1024, false);
        memory.createInitializedBlock(
            "pointer_tail_seed", toAddr(0xb001), 1, (byte) 0, monitor, false);
        var manager = currentProgram.getDataTypeManager();
        var raw = new StructureDataType("MappedPointer", 8, manager);
        raw.replaceAtOffset(0, new ArrayDataType(ByteDataType.dataType, 8, 1), 8, "value", null);
        var data = listing.createData(start, raw);
        // A normal field edit can introduce a pointer without evaluating its
        // value. Its direct first byte can be edited independently of the tail.
        ((Structure) data.getDataType())
            .replaceAtOffset(0, new PointerDataType(null, 8, manager), 8, "value", null);
        break;
      case "verify":
        var retained = listing.getDefinedDataAt(start);
        if (retained == null
            || !(retained.getDataType() instanceof Structure)
            || !(retained.getComponent(0).getDataType()
                instanceof ghidra.program.model.data.Pointer))
          throw new IllegalStateException("Pointer definition was lost");
        var refs = currentProgram.getReferenceManager().getReferencesFrom(start);
        if (refs.length != 1
            || !refs[0].getToAddress().equals(toAddr(0x19))
            || refs[0].getSource() != SourceType.DEFAULT)
          throw new IllegalStateException("Pointer reference was not updated");
        break;
      case "remove":
        // Native program-open probes cannot traverse this deep self mapping.
        memory.removeBlock(memory.getBlock(toAddr(0x7001)), monitor);
        memory.removeBlock(memory.getBlock(toAddr(0xb001)), monitor);
        memory.removeBlock(memory.getBlock(start), monitor);
        break;
      default:
        throw new IllegalArgumentException(getScriptArgs()[0]);
    }
  }
}
