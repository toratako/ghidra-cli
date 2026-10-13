import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;

public class CreateMappedNativeReaders extends GhidraScript {
  public void run() throws Exception {
    var memory = currentProgram.getMemory();
    memory.createInitializedBlock("targets", toAddr(0x3000), 0x40, (byte) 0xee, monitor, false);
    memory.createByteMappedBlock("tables_alias", toAddr(0x2000), toAddr(0x1000), 12, false);
    memory.createByteMappedBlock("tables_nested", toAddr(0x1800), toAddr(0x2000), 12, false);
    memory.createByteMappedBlock("tables_cycle", toAddr(0x4000), toAddr(0x4000), 12, false);
    memory.createInitializedBlock(
        "code",
        toAddr(0x5000),
        new java.io.ByteArrayInputStream(new byte[] {(byte) 0x90, (byte) 0xc3}),
        2,
        monitor,
        false);
    memory.createByteMappedBlock("code_alias", toAddr(0x6000), toAddr(0x5000), 2, false);
    memory.createByteMappedBlock("code_nested", toAddr(0x5500), toAddr(0x6000), 2, false);
    var command = new DisassembleCommand(toAddr(0x6000), null, true);
    command.enableCodeAnalysis(false);
    if (!command.applyTo(currentProgram, monitor))
      throw new IllegalStateException("Cannot decode mapped fixture instructions");
    // Native disassembly omits nested aliases from its initialized set.
    // Place already decoded instructions to exercise the listing reader.
    for (int i = 0; i < 2; i++) {
      var instruction = currentProgram.getListing().getInstructionAt(toAddr(0x6000 + i));
      currentProgram
          .getListing()
          .createInstruction(
              toAddr(0x5500 + i),
              instruction.getPrototype(),
              new ghidra.program.model.mem.DumbMemBufferImpl(memory, toAddr(0x5500 + i)),
              instruction,
              0);
    }
    memory.getBlock(toAddr(0x5500)).setExecute(true);
    memory.createInitializedBlock(
        "caller",
        toAddr(0x7000),
        new java.io.ByteArrayInputStream(
            new byte[] {(byte) 0xe8, (byte) 0xfb, (byte) 0xe4, (byte) 0xff, (byte) 0xff}),
        5,
        monitor,
        false);
    var call = new DisassembleCommand(toAddr(0x7000), null, false);
    call.enableCodeAnalysis(false);
    if (!call.applyTo(currentProgram, monitor))
      throw new IllegalStateException("Cannot define caller");
    memory.createInitializedBlock("shifted_seed", toAddr(0x8000), 1, (byte) 0xc3, monitor, false);
    memory.createByteMappedBlock("shifted_table", toAddr(0x8001), toAddr(0x8000), 16 * 1024, false);
    memory.createInitializedBlock(
        "shifted_target", toAddr(0xc3c3c3c3L), 16, (byte) 0xee, monitor, false);
    var ret = currentProgram.getListing().getInstructionAt(toAddr(0x6001));
    currentProgram
        .getListing()
        .createInstruction(
            toAddr(0xc000),
            ret.getPrototype(),
            new ghidra.program.model.mem.ByteMemBufferImpl(
                memory, toAddr(0xc000), new byte[] {(byte) 0xc3}, false),
            ret,
            0);
    memory.createInitializedBlock("string_seed", toAddr(0xd000), 1, (byte) 0, monitor, false);
    memory.createByteMappedBlock(
        "shifted_string", toAddr(0xd001), toAddr(0xd000), 16 * 1024, false);
    currentProgram
        .getListing()
        .createData(toAddr(0x11000), ghidra.program.model.data.ByteDataType.dataType, 1);
  }
}
