
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.symbol.SourceType;
public class DefineExportCoverageFixture extends GhidraScript {
    public void run() throws Exception {
        currentProgram.getMemory().getBlock(toAddr(0x1000)).setWrite(true);
        createData(toAddr(0x1010), DWordDataType.dataType);
        createLabel(toAddr(0x1010), "referenced_value", true);
        createData(toAddr(0x1014), DWordDataType.dataType);
        createLabel(toAddr(0x1014), "unreferenced_value", true);
        if (!disassemble(toAddr(0x1000))) {
            throw new IllegalStateException("Could not disassemble fixture");
        }
        var function = createFunction(toAddr(0x1000), "read_global");
        function.setReturnType(DWordDataType.dataType, SourceType.USER_DEFINED);
        currentProgram.getMemory().createUninitializedBlock("uninitialized",
            toAddr(0x2000), 32, false);
    }
}
