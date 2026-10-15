import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSet;

public class RebaseRangePropertyMaps extends GhidraScript {
  public void run() throws Exception {
    String[] args = getScriptArgs();
    String kind = args[0];
    var space = currentProgram.getAddressFactory().getDefaultAddressSpace();
    long offset = Long.parseUnsignedLong(args[1], 16);
    var start = space.getAddress(offset);
    var end = start.add(15);
    String name = "rebase_range_property";
    if (args[2].equals("create")) {
      if (kind.equals("address set")) {
        currentProgram.createAddressSetPropertyMap(name).add(start, end);
      } else {
        currentProgram.createIntRangeMap(name).setValue(start, end, 42);
      }
    } else {
      var actual =
          kind.equals("address set")
              ? currentProgram.getAddressSetPropertyMap(name).getAddressSet()
              : currentProgram.getIntRangeMap(name).getAddressSet(42);
      if (!actual.equals(new AddressSet(start, end))) {
        throw new IllegalStateException("Range property moved unexpectedly: " + actual);
      }
    }
  }
}
