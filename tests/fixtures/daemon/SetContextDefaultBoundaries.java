
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.DefaultProgramContext;
import ghidra.program.model.lang.RegisterValue;
import java.math.BigInteger;
public class SetContextDefaultBoundaries extends GhidraScript {
    public void run() throws Exception {
        var context = currentProgram.getProgramContext();
        ((DefaultProgramContext) context).setDefaultValue(
            new RegisterValue(currentProgram.getRegister("TMode"), BigInteger.ONE),
            toAddr(0x3004), toAddr(0x3007));
        context.setRegisterValue(toAddr(0x4020), toAddr(0x4020),
            new RegisterValue(context.getBaseContextRegister(),
                new BigInteger("f00000000000000a", 16), new BigInteger("f00000000000000f", 16)));
    }
}
