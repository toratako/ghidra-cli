import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.util.DefaultLanguageService;

public class CreateDisasmFailureFixture extends GhidraScript {
  public void run() throws Exception {
    var language =
        DefaultLanguageService.getLanguageService()
            .getLanguage(new LanguageID("x86:LE:64:default"));
    var program =
        new ProgramDB(getScriptArgs()[0], language, language.getDefaultCompilerSpec(), this);
    try {
      int tx = program.startTransaction("disassembly fixture");
      try {
        var address = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000);
        var block =
            program
                .getMemory()
                .createInitializedBlock("code", address, 1, (byte) 0xc3, monitor, false);
        block.setExecute(true);
        var longStart = address.add(0x1000);
        program
            .getMemory()
            .createInitializedBlock("long_code", longStart, 21, (byte) 0x90, monitor, false)
            .setExecute(true);
        // Alternate one-byte NOP/CLC to avoid Ghidra's repeated-byte guard.
        for (int offset = 1; offset < 20; offset += 2) {
          program.getMemory().setByte(longStart.add(offset), (byte) 0xf8);
        }
        program.getMemory().setByte(longStart.add(20), (byte) 0xc3);
        var flowStart = address.add(0x2000);
        byte[] flow = new byte[0x31];
        java.util.Arrays.fill(flow, (byte) 0xcc);
        // 0x3000 -> 0x3010; NOP then 0x3011 -> 0x3000 (a loop).
        byte[] jump = {(byte) 0xe9, 0x0b, 0, 0, 0};
        System.arraycopy(jump, 0, flow, 0, jump.length);
        flow[0x10] = (byte) 0x90;
        byte[] back = {(byte) 0xe9, (byte) 0xea, (byte) 0xff, (byte) 0xff, (byte) 0xff};
        System.arraycopy(back, 0, flow, 0x11, back.length);
        // 0x3020 -> 0x3030, outside the first requested range.
        System.arraycopy(jump, 0, flow, 0x20, jump.length);
        flow[0x30] = (byte) 0xc3;
        program
            .getMemory()
            .createInitializedBlock(
                "flow",
                flowStart,
                new java.io.ByteArrayInputStream(flow),
                flow.length,
                monitor,
                false)
            .setExecute(true);
        byte[] boundary = {0x66, (byte) 0x90, (byte) 0xc3};
        program
            .getMemory()
            .createInitializedBlock(
                "boundary",
                address.add(0x3000),
                new java.io.ByteArrayInputStream(boundary),
                boundary.length,
                monitor,
                false)
            .setExecute(true);
        byte[] partial = {(byte) 0x90, (byte) 0xb8, 1, 0, 0, 0, (byte) 0xc3};
        program
            .getMemory()
            .createInitializedBlock(
                "partial",
                address.add(0x3100),
                new java.io.ByteArrayInputStream(partial),
                partial.length,
                monitor,
                false)
            .setExecute(true);
        byte[] call = new byte[0x11];
        java.util.Arrays.fill(call, (byte) 0x90);
        call[0] = (byte) 0xe8;
        call[1] = 0x0b;
        call[2] = 0;
        call[3] = 0;
        call[4] = 0;
        call[0x10] = (byte) 0xc3;
        var callStart = address.add(0x4000);
        program
            .getMemory()
            .createInitializedBlock(
                "noreturn",
                callStart,
                new java.io.ByteArrayInputStream(call),
                call.length,
                monitor,
                false)
            .setExecute(true);
        var callee = callStart.add(0x10);
        new ghidra.app.cmd.disassemble.DisassembleCommand(callee, null, false)
            .applyTo(program, monitor);
        program
            .getFunctionManager()
            .createFunction(
                "noreturn_target",
                callee,
                new ghidra.program.model.address.AddressSet(callee, callee),
                ghidra.program.model.symbol.SourceType.USER_DEFINED)
            .setNoReturn(true);
        program
            .getSymbolTable()
            .createLabel(
                longStart, "code_start", ghidra.program.model.symbol.SourceType.USER_DEFINED);
        program
            .getSymbolTable()
            .createLabel(
                longStart.add(11), "code_end", ghidra.program.model.symbol.SourceType.USER_DEFINED);
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
