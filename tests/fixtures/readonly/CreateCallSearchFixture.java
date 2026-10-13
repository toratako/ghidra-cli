import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;

public class CreateCallSearchFixture extends GhidraScript {
  public void run() throws Exception {
    var language =
        DefaultLanguageService.getLanguageService()
            .getLanguage(new LanguageID("x86:LE:64:default"));
    var program =
        new ProgramDB(getScriptArgs()[0], language, language.getDefaultCompilerSpec(), this);
    try {
      int tx = program.startTransaction("call search fixture");
      try {
        var space = program.getAddressFactory().getDefaultAddressSpace();
        var fm = program.getFunctionManager();
        var refs = program.getReferenceManager();
        var source = SourceType.USER_DEFINED;
        program
            .getMemory()
            .createInitializedBlock(
                "code", space.getAddress(0x1000), 0x3000, (byte) 0, monitor, false);
        String[] names = {"search_caller", "search_helper", "search_leaf"};
        for (int i = 0; i < names.length; i++) {
          var entry = space.getAddress(0x1000 + i * 0x100);
          fm.createFunction(names[i], entry, new AddressSet(entry, entry.add(0xff)), source);
        }
        for (int address :
            new int[] {
              0x1000, 0x1008, 0x1010, 0x1100, 0x1060, 0x1090, 0x1098, 0x10a0, 0x10a8, 0x10b0,
              0x10b8, 0x10c0, 0x2100, 0x2500
            }) {
          var site = space.getAddress(address);
          program.getMemory().setBytes(site, new byte[] {(byte) 0xff, (byte) 0xd0});
          if (!new DisassembleCommand(site, new AddressSet(site, site.add(1)), false)
              .applyTo(program, monitor)) {
            throw new IllegalStateException("Could not disassemble call at " + site);
          }
        }
        refs.addMemoryReference(
            space.getAddress(0x1000),
            space.getAddress(0x1100),
            RefType.UNCONDITIONAL_CALL,
            source,
            0);
        refs.addMemoryReference(
            space.getAddress(0x1100),
            space.getAddress(0x1200),
            RefType.UNCONDITIONAL_CALL,
            source,
            0);
        var external =
            program
                .getExternalManager()
                .addExtFunction("KERNEL32.dll", "CreateProcessA", null, source);
        var thunkEntry = space.getAddress(0x2000);
        var thunk =
            fm.createFunction(
                "CreateProcessA",
                thunkEntry,
                new AddressSet(thunkEntry, thunkEntry.add(5)),
                source);
        thunk.setThunkedFunction(external.getFunction());
        var localThunkEntry = space.getAddress(0x2050);
        var localThunk =
            fm.createFunction(
                "helper_thunk",
                localThunkEntry,
                new AddressSet(localThunkEntry, localThunkEntry.add(5)),
                source);
        localThunk.setThunkedFunction(fm.getFunctionAt(space.getAddress(0x1100)));
        refs.addExternalReference(
            space.getAddress(0x1008), 0, external, source, RefType.UNCONDITIONAL_CALL);
        refs.addMemoryReference(
            space.getAddress(0x1010), thunkEntry, RefType.UNCONDITIONAL_CALL, source, 0);
        var slot = space.getAddress(0x3000);
        program.getListing().createData(slot, PointerDataType.dataType);
        refs.addExternalReference(slot, 0, external, source, RefType.DATA);
        var indirect = space.getAddress(0x1020);
        program
            .getMemory()
            .setBytes(indirect, new byte[] {(byte) 0xff, 0x15, (byte) 0xda, 0x1f, 0, 0});
        new DisassembleCommand(indirect, new AddressSet(indirect, indirect.add(5)), false)
            .applyTo(program, monitor);
        refs.addMemoryReference(indirect, slot, RefType.READ, source, 0);
        // A pointer to local code can use the flow-type INDIRECTION.
        var localSlot = space.getAddress(0x3010);
        program.getListing().createData(localSlot, PointerDataType.dataType);
        refs.addMemoryReference(
            localSlot, space.getAddress(0x1100), RefType.INDIRECTION, source, 0);
        var localIndirect = space.getAddress(0x1040);
        program
            .getMemory()
            .setBytes(localIndirect, new byte[] {(byte) 0xff, 0x15, (byte) 0xca, 0x1f, 0, 0});
        if (!new DisassembleCommand(
                localIndirect, new AddressSet(localIndirect, localIndirect.add(5)), false)
            .applyTo(program, monitor)) {
          throw new IllegalStateException("Could not disassemble local indirect call");
        }
        refs.addMemoryReference(localIndirect, localSlot, RefType.READ, source, 0);
        // References from pointer leaves inside aggregates must be followed too.
        var record = new StructureDataType("CallRecord", 0);
        record.add(IntegerDataType.dataType, "tag", null);
        record.add(PointerDataType.dataType, "target", null);
        var recordSlot = space.getAddress(0x3050);
        program.getListing().createData(recordSlot, record);
        refs.addMemoryReference(
            recordSlot.add(4), space.getAddress(0x1100), RefType.DATA, source, 0);
        var arraySlot = space.getAddress(0x3070);
        program
            .getListing()
            .createData(arraySlot, new ArrayDataType(PointerDataType.dataType, 2, 8));
        refs.addMemoryReference(
            arraySlot.add(8), space.getAddress(0x1200), RefType.DATA, source, 0);
        for (int[] edge : new int[][] {{0x10e0, 0x3054}, {0x10e8, 0x3078}}) {
          var site = space.getAddress(edge[0]);
          program.getMemory().setBytes(site, new byte[] {(byte) 0xff, (byte) 0xd0});
          if (!new DisassembleCommand(site, new AddressSet(site, site.add(1)), false)
              .applyTo(program, monitor)) {
            throw new IllegalStateException("Could not disassemble aggregate indirect call");
          }
          refs.addMemoryReference(site, space.getAddress(edge[1]), RefType.READ, source, 0);
        }
        program.getSymbolTable().createLabel(slot, "__imp_CreateProcessA", source);
        // Interior and undefined destinations, an unowned call site, and a disjoint body.
        refs.addMemoryReference(
            space.getAddress(0x1090),
            space.getAddress(0x1204),
            RefType.UNCONDITIONAL_CALL,
            source,
            0);
        refs.addMemoryReference(
            space.getAddress(0x1098),
            space.getAddress(0x2200),
            RefType.UNCONDITIONAL_CALL,
            source,
            0);
        refs.addMemoryReference(
            space.getAddress(0x2100),
            space.getAddress(0x1100),
            RefType.UNCONDITIONAL_CALL,
            source,
            0);
        var body = new AddressSet(fm.getFunctionAt(space.getAddress(0x1000)).getBody());
        body.add(space.getAddress(0x2500), space.getAddress(0x2501));
        fm.getFunctionAt(space.getAddress(0x1000)).setBody(body);
        refs.addMemoryReference(
            space.getAddress(0x2500),
            space.getAddress(0x1200),
            RefType.UNCONDITIONAL_CALL,
            source,
            0);
        // A pointer table inside another function must still resolve as a pointer.
        var leafBody = new AddressSet(fm.getFunctionAt(space.getAddress(0x1200)).getBody());
        leafBody.add(localSlot, localSlot.add(7));
        fm.getFunctionAt(space.getAddress(0x1200)).setBody(leafBody);
        // Multiple known destinations must survive, while duplicate evidence is one call.
        refs.addMemoryReference(
            space.getAddress(0x10a8), space.getAddress(0x1100), RefType.COMPUTED_CALL, source, 0);
        refs.addMemoryReference(
            space.getAddress(0x10a8), space.getAddress(0x1200), RefType.COMPUTED_CALL, source, 0);
        refs.addMemoryReference(
            space.getAddress(0x10a8), space.getAddress(0x1204), RefType.COMPUTED_CALL, source, 0);
        refs.addMemoryReference(space.getAddress(0x10b0), slot, RefType.READ, source, 0);
        refs.addExternalReference(
            space.getAddress(0x10b0), 1, external, source, RefType.COMPUTED_CALL);
        // Pointer chains resolve in both directions; pointer cycles terminate.
        var chainedSlot = space.getAddress(0x3020);
        program.getListing().createData(chainedSlot, PointerDataType.dataType);
        refs.addMemoryReference(chainedSlot, slot, RefType.DATA, source, 0);
        refs.addMemoryReference(space.getAddress(0x10a0), chainedSlot, RefType.READ, source, 0);
        for (int address : new int[] {0x3030, 0x3040}) {
          program.getListing().createData(space.getAddress(address), PointerDataType.dataType);
        }
        refs.addMemoryReference(
            space.getAddress(0x3030), space.getAddress(0x3040), RefType.DATA, source, 0);
        refs.addMemoryReference(
            space.getAddress(0x3040), space.getAddress(0x3030), RefType.DATA, source, 0);
        refs.addMemoryReference(
            space.getAddress(0x10b8), space.getAddress(0x3030), RefType.READ, source, 0);
        // Native operand-storage references do not identify runtime call targets.
        var registerCall = space.getAddress(0x10f0);
        program.getMemory().setBytes(registerCall, new byte[] {(byte) 0xff, (byte) 0xd0});
        if (!new DisassembleCommand(
                registerCall, new AddressSet(registerCall, registerCall.add(1)), false)
            .applyTo(program, monitor)) {
          throw new IllegalStateException("Could not disassemble register indirect call");
        }
        refs.addRegisterReference(
            registerCall, 0, program.getRegister("RAX"), RefType.READ, source);
        var stackCall = space.getAddress(0x10f8);
        program.getMemory().setBytes(stackCall, new byte[] {(byte) 0xff, 0x54, 0x24, 0x20});
        if (!new DisassembleCommand(stackCall, new AddressSet(stackCall, stackCall.add(3)), false)
            .applyTo(program, monitor)) {
          throw new IllegalStateException("Could not disassemble stack indirect call");
        }
        refs.addStackReference(stackCall, 0, 0x20, RefType.READ, source);
        // Argument references do not call the API, including on an unrelated CALL.
        for (int address : new int[] {0x1030, 0x1050, 0x1070, 0x10c8, 0x10d0}) {
          var site = space.getAddress(address);
          program.getMemory().setByte(site, (byte) 0x90);
          new DisassembleCommand(site, new AddressSet(site, site), false).applyTo(program, monitor);
        }
        refs.addExternalReference(space.getAddress(0x1030), 0, external, source, RefType.DATA);
        refs.addExternalReference(space.getAddress(0x1050), 0, external, source, RefType.PARAM);
        refs.addExternalReference(space.getAddress(0x1060), 0, external, source, RefType.PARAM);
        var override =
            refs.addMemoryReference(
                space.getAddress(0x10c0),
                space.getAddress(0x1200),
                RefType.CALL_OVERRIDE_UNCONDITIONAL,
                source,
                0);
        refs.setPrimary(override, true);
        // A local call override also supersedes stale external relocation evidence.
        refs.addExternalReference(
            space.getAddress(0x10c0), 1, external, source, RefType.COMPUTED_CALL);
        var inactive =
            refs.addMemoryReference(
                space.getAddress(0x10c8),
                space.getAddress(0x1200),
                RefType.CALL_OVERRIDE_UNCONDITIONAL,
                source,
                0);
        refs.setPrimary(inactive, false);
        // A primary call override on NOP has no CALL/CALLIND to override.
        var inert =
            refs.addMemoryReference(
                space.getAddress(0x10d0),
                space.getAddress(0x1200),
                RefType.CALL_OVERRIDE_UNCONDITIONAL,
                source,
                0);
        refs.setPrimary(inert, true);
        // A direct call can have symbolic EXTERNAL relocation evidence,
        // whose EXTERNAL address is not represented in memory-space p-code.
        var relocated = space.getAddress(0x10d8);
        program.getMemory().setBytes(relocated, new byte[] {(byte) 0xe8, 0x23, 1, 0, 0});
        if (!new DisassembleCommand(relocated, new AddressSet(relocated, relocated.add(4)), false)
            .applyTo(program, monitor)) {
          throw new IllegalStateException("Could not disassemble relocated call");
        }
        if (!program.getListing().getInstructionAt(relocated).getFlowType().isCall()) {
          throw new IllegalStateException("Relocated instruction must be an effective CALL");
        }
        refs.removeAllReferencesFrom(relocated);
        refs.addExternalReference(relocated, 0, external, source, RefType.UNCONDITIONAL_CALL);
        // Even a mislabeled CALL reference from a NOP or undefined bytes is not a call.
        refs.addExternalReference(
            space.getAddress(0x1070), 0, external, source, RefType.UNCONDITIONAL_CALL);
        refs.addExternalReference(
            space.getAddress(0x1080), 0, external, source, RefType.UNCONDITIONAL_CALL);
      } finally {
        program.endTransaction(tx, true);
      }
      state
          .getProject()
          .getProjectData()
          .getRootFolder()
          .createFile(getScriptArgs()[0], program, monitor);
    } finally {
      program.release(this);
    }
  }
}
