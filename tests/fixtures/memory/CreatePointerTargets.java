import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.symbol.SourceType;

public class CreatePointerTargets extends GhidraScript {
  public void run() throws Exception {
    String[] args = getScriptArgs();
    String[] names = {"outside_range_target", "high_address_target", "odd_address_target"};
    var namespace =
        currentProgram
            .getSymbolTable()
            .createNameSpace(null, "pointer_fixture", SourceType.USER_DEFINED);
    for (int i = 0; i < args.length; i++) {
      var address =
          currentProgram
              .getAddressFactory()
              .getDefaultAddressSpace()
              .getAddress(Long.parseUnsignedLong(args[i], 16));
      var block =
          currentProgram
              .getMemory()
              .createInitializedBlock(names[i], address, 4, (byte) 0, monitor, false);
      block.setExecute(true);
      var thumbMode = currentProgram.getRegister("TMode");
      if (thumbMode != null) {
        currentProgram
            .getProgramContext()
            .setValue(thumbMode, address, address.add(3), java.math.BigInteger.ONE);
      }
      var function =
          currentProgram
              .getFunctionManager()
              .createFunction(
                  names[i],
                  address,
                  new AddressSet(address, address.add(3)),
                  SourceType.USER_DEFINED);
      if (i == 1) function.setParentNamespace(namespace);
    }
    var space = currentProgram.getAddressFactory().getDefaultAddressSpace();
    var functions = currentProgram.getFunctionManager();
    var target = functions.getFunctionAt(space.getAddress(Long.parseUnsignedLong(args[1], 16)));
    for (int i = 1; i >= 0; i--) {
      var address = space.getAddress(0x5000 + i * 0x10);
      var name = i == 0 ? "first_thunk" : "second_thunk";
      var block =
          currentProgram
              .getMemory()
              .createInitializedBlock(name, address, 4, (byte) 0, monitor, false);
      block.setExecute(true);
      var thunk =
          functions.createFunction(
              name,
              namespace,
              address,
              new AddressSet(address, address.add(3)),
              SourceType.USER_DEFINED);
      thunk.setThunkedFunction(target);
      target = thunk;
    }
    currentProgram
        .getSymbolTable()
        .createLabel(space.getAddress(0x1000), "table_data", namespace, SourceType.USER_DEFINED);
    currentProgram
        .getMemory()
        .createUninitializedBlock("uninitialized_data", space.getAddress(0x6000), 4, false);
    currentProgram
        .getSymbolTable()
        .createLabel(
            space.getAddress(0x6000), "uninitialized_data", namespace, SourceType.USER_DEFINED);
  }
}
