
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.reloc.Relocation.Status;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import java.math.BigInteger;

public class UnmappedRebaseMetadata extends GhidraScript {
    public void run() throws Exception {
        var p = currentProgram;
        var space = p.getAddressFactory().getDefaultAddressSpace();
        var high = space.getAddress(0xfffffffffffff000L);
        var code = space.getAddress(0x2000);
        if (p.getMemory().contains(high)) throw new IllegalStateException("Expected unmapped address");
        switch (getScriptArgs()[0]) {
            case "symbol":
                p.getSymbolTable().createLabel(high, "unmapped", SourceType.USER_DEFINED); break;
            case "reference source":
                p.getReferenceManager().addMemoryReference(high, code, RefType.DATA, SourceType.USER_DEFINED, 0); break;
            case "reference destination":
                p.getReferenceManager().addMemoryReference(code.add(0x40), high, RefType.DATA, SourceType.USER_DEFINED, 0); break;
            case "comment":
                p.getListing().setComment(high, CodeUnit.EOL_COMMENT, "unmapped comment"); break;
            case "register context":
                var register = p.getProgramContext().getBaseContextRegister();
                p.getProgramContext().setRegisterValue(high, high, new RegisterValue(register, BigInteger.ONE)); break;
            case "bookmark":
                p.getBookmarkManager().setBookmark(high, "Note", "rebase", "unmapped bookmark"); break;
            case "user property":
                p.getUsrPropertyManager().createIntPropertyMap("rebase_property").add(high, 7); break;
            case "relocation":
                p.getRelocationTable().add(high, Status.SKIPPED, 17, new long[]{0x2000},
                    new byte[]{1, 2, 3, 4}, "unmapped relocation"); break;
            case "equate reference":
                p.getEquateTable().createEquate("unmapped_equate", 7).addReference(high, 0); break;
            case "function body":
                var function = p.getFunctionManager().getFunctionAt(code);
                var body = new AddressSet(function.getBody());
                body.add(high);
                function.setBody(body); break;
            case "pinned":
                p.getSymbolTable().createLabel(high, "pinned", SourceType.USER_DEFINED).setPinned(true); break;
            case "check pinned":
                var symbols = p.getSymbolTable().getSymbols(high);
                if (symbols.length != 1 || !symbols[0].getName().equals("pinned") || !symbols[0].isPinned()) {
                    throw new IllegalStateException("Pinned label moved");
                }
                break;
            default: throw new IllegalArgumentException(getScriptArgs()[0]);
        }
    }
}
