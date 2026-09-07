package ghidracli;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

final class AddressResolver {
    private final ProgramSession session;

    AddressResolver(ProgramSession session) {
        this.session = session;
    }

    private static final Pattern NAMED_HEX_ADDRESS_PATTERN =
        Pattern.compile("(?i)^(?:FUN|SUB|LAB|DAT)_([0-9a-f]+)$");

    Address resolveAddress(String addrStr) {
        if (session.program() == null || addrStr == null || addrStr.isEmpty()) {
            return null;
        }

        String target = addrStr.trim();
        AddressFactory af = session.program().getAddressFactory();

        // Try as hex address first (with and without 0x prefix)
        Address addr = af.getAddress(target);
        if (addr != null) {
            return addr;
        }
        if (target.startsWith("0x") || target.startsWith("0X")) {
            addr = af.getAddress(target.substring(2));
            if (addr != null) {
                return addr;
            }
        }

        // Parse common Ghidra auto names like FUN_00401234 as raw addresses.
        Matcher namedHex = NAMED_HEX_ADDRESS_PATTERN.matcher(target);
        if (namedHex.matches()) {
            String hexPart = namedHex.group(1);
            addr = af.getAddress(hexPart);
            if (addr == null) {
                addr = af.getAddress("0x" + hexPart);
            }
            if (addr != null) {
                return addr;
            }
        }

        // Try as symbol/function name via SymbolTable. Prefer concrete program
        // addresses, but remember an external-space address as a fallback so
        // import names (e.g. CreateThread/puts) can be used directly with xref
        // commands. External symbols previously resolved to null, forcing
        // callers to look up the import address manually first.
        SymbolTable st = session.program().getSymbolTable();
        Address externalCandidate = null;
        SymbolIterator syms = st.getSymbols(target);
        while (syms.hasNext()) {
            Symbol sym = syms.next();
            Address symAddr = sym.getAddress();
            if (symAddr == null) continue;
            if (!symAddr.isExternalAddress()) {
                return symAddr;
            }
            if (externalCandidate == null) {
                externalCandidate = symAddr;
            }
        }

        // Try global symbols (may include exports/imports). Again prefer a real
        // program address over an external-space symbol with the same name.
        List<Symbol> globalSyms = st.getGlobalSymbols(target);
        for (Symbol sym : globalSyms) {
            Address symAddr = sym.getAddress();
            if (symAddr == null) continue;
            if (!symAddr.isExternalAddress()) {
                return symAddr;
            }
            if (externalCandidate == null) {
                externalCandidate = symAddr;
            }
        }

        // Fallback: scan functions by name (O(n) but handles edge cases).
        FunctionManager fm = session.program().getFunctionManager();
        FunctionIterator iter = fm.getFunctions(true);
        while (iter.hasNext()) {
            Function func = iter.next();
            if (func.getName().equals(target)) {
                return func.getEntryPoint();
            }
        }

        return externalCandidate;
    }

    /**
     * Resolve every address that can represent an xref target. Import names may
     * have both an EXTERNAL-space symbol and one or more local thunk/IAT
     * functions. References usually point at the local thunk, so resolving only
     * the external symbol misses the actual call sites.
     */
    LinkedHashSet<Address> resolveXrefTargets(String target) {
        LinkedHashSet<Address> targets = new LinkedHashSet<>();
        if (session.program() == null || target == null || target.trim().isEmpty()) {
            return targets;
        }

        Address primary = resolveAddress(target);
        if (primary != null) {
            targets.add(primary);
        }

        SymbolTable st = session.program().getSymbolTable();
        SymbolIterator syms = st.getSymbols(target.trim());
        while (syms.hasNext()) {
            Address a = syms.next().getAddress();
            if (a != null) targets.add(a);
        }
        for (Symbol sym : st.getGlobalSymbols(target.trim())) {
            Address a = sym.getAddress();
            if (a != null) targets.add(a);
        }

        // Add local thunk functions that ultimately dispatch to any resolved
        // external function. This is the address call references normally target
        // in PE/ELF imports.
        Set<Address> externalEntries = new HashSet<>();
        for (Address a : targets) {
            if (a.isExternalAddress()) externalEntries.add(a);
        }
        if (!externalEntries.isEmpty()) {
            FunctionManager fm = session.program().getFunctionManager();
            FunctionIterator funcs = fm.getFunctions(true);
            while (funcs.hasNext()) {
                Function f = funcs.next();
                if (!f.isThunk()) continue;
                Function thunked = f.getThunkedFunction(true);
                if (thunked != null && externalEntries.contains(thunked.getEntryPoint())) {
                    targets.add(f.getEntryPoint());
                }
            }
        }

        return targets;
    }
}
