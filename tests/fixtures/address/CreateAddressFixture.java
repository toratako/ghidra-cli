import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.symbol.SourceType;

public class CreateAddressFixture extends GhidraScript {
  public void run() throws Exception {
    var space = currentProgram.getAddressFactory().getDefaultAddressSpace();
    var memory = currentProgram.getMemory();
    var functions = currentProgram.getFunctionManager();
    String[] names = {
      "add",
      "dead",
      "12345",
      "FUN_00001400",
      "malformed_target",
      "literal_add",
      "literal_dead",
      "literal_digits"
    };
    long[] offsets = {0x1000, 0x1100, 0x1200, 0x1400, 0x1500, 0xadd, 0xdead, 0x12345};
    for (int i = 0; i < names.length; i++) {
      var address = space.getAddress(offsets[i]);
      if (!memory.contains(address)) {
        memory.createInitializedBlock(names[i], address, 1, (byte) 0xc3, monitor, false);
      }
      memory.getBlock(address).setExecute(true);
      int length = i < 2 ? 6 : 1;
      if (i < 2) {
        // A real x86 CALL to the next named function, followed by RET.
        memory.setBytes(address, new byte[] {(byte) 0xe8, (byte) 0xfb, 0, 0, 0, (byte) 0xc3});
      }
      if (!new DisassembleCommand(address, null, false).applyTo(currentProgram, monitor)) {
        throw new IllegalStateException("Disassembly failed for " + names[i]);
      }
      if (i < 2)
        new DisassembleCommand(address.add(5), null, false).applyTo(currentProgram, monitor);
      functions.createFunction(
          names[i],
          address,
          new AddressSet(address, address.add(length - 1)),
          SourceType.USER_DEFINED);
    }
    var symbols = currentProgram.getSymbolTable();
    symbols.createLabel(space.getAddress(0x1000), "ambiguous", SourceType.USER_DEFINED);
    symbols.createLabel(space.getAddress(0x1100), "ambiguous", SourceType.USER_DEFINED);
    symbols.createLabel(space.getAddress(0x1000), "entry_alias", SourceType.USER_DEFINED);
    symbols.createLabel(space.getAddress(0x1005), "interior_label", SourceType.USER_DEFINED);
    symbols.createLabel(space.getAddress(0x1005), "FUN_00001400", SourceType.USER_DEFINED);
    for (int i = 0; i < 2; i++) {
      var namespace = symbols.createNameSpace(null, "scope" + i, SourceType.USER_DEFINED);
      var address = space.getAddress(0x1300 + i * 0x10);
      functions.createFunction(
          "ambiguous",
          namespace,
          address,
          new AddressSet(address, address),
          SourceType.USER_DEFINED);
    }
    for (String name : new String[] {"0x", "0X", "0xnothex", "0x1000junk"}) {
      symbols.createLabel(space.getAddress(0x1500), name, SourceType.USER_DEFINED);
    }
    var scope = symbols.getNamespace("scope0", null);
    symbols.createLabel(space.getAddress(0x1601), "handler<ns::Item>", SourceType.USER_DEFINED);
    symbols.createLabel(
        space.getAddress(0x1602), "scoped<ns::Item>", scope, SourceType.USER_DEFINED);
    symbols.createLabel(space.getAddress(0x1603), "scope0::collision", SourceType.USER_DEFINED);
    symbols.createLabel(space.getAddress(0x1604), "collision", scope, SourceType.USER_DEFINED);
    symbols.createLabel(space.getAddress(0x1605), "scope0", scope, SourceType.USER_DEFINED);
    var external =
        currentProgram
            .getExternalManager()
            .addExtFunction("lookup", "lookup_external", null, SourceType.IMPORTED)
            .getFunction();
    var thunkEntry = space.getAddress(0x1606);
    var thunk =
        functions.createFunction(
            "lookup_thunk", thunkEntry, new AddressSet(thunkEntry), SourceType.USER_DEFINED);
    thunk.setThunkedFunction(external);
    symbols.createLabel(space.getAddress(0x1607), "0xentry", scope, SourceType.USER_DEFINED);
    symbols.createLabel(space.getAddress(0x1608), "handler<ns::0xItem>", SourceType.USER_DEFINED);
    symbols.createLabel(space.getAddress(0x1609), "scope0::0xcollision", SourceType.USER_DEFINED);
    symbols.createLabel(space.getAddress(0x160a), "0xcollision", scope, SourceType.USER_DEFINED);
    currentProgram
        .getReferenceManager()
        .addMemoryReference(
            space.getAddress(0x1500),
            space.getAddress(0x1610),
            ghidra.program.model.symbol.RefType.DATA,
            SourceType.USER_DEFINED,
            0);
    var generatedOwner =
        functions.createFunction(
            "generated_owner",
            space.getAddress(0x1620),
            new AddressSet(space.getAddress(0x1620)),
            SourceType.USER_DEFINED);
    generatedOwner.addParameter(
        new ghidra.program.model.listing.ParameterImpl(
            null, ghidra.program.model.data.IntegerDataType.dataType, currentProgram),
        SourceType.DEFAULT);
    generatedOwner.addLocalVariable(
        new ghidra.program.model.listing.LocalVariableImpl(
            null, ghidra.program.model.data.IntegerDataType.dataType, -4, currentProgram),
        SourceType.DEFAULT);
  }
}
