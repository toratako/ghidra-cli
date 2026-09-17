package ghidracli;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Set;

final class AddressResolver {
    private final ProgramSession session;

    AddressResolver(ProgramSession session) {
        this.session = session;
    }

    Address parseAddress(String addrStr) {
        return session.program() == null ? null
            : AddressCodec.parse(session.program().getAddressFactory(), addrStr);
    }

    LinkedHashSet<Address> namedAddresses(String target) {
        LinkedHashSet<Address> candidates = new LinkedHashSet<>();
        SymbolTable st = session.program().getSymbolTable();
        SymbolIterator syms = st.getSymbols(target);
        while (syms.hasNext()) {
            Address address = syms.next().getAddress();
            if (address != null) candidates.add(address);
        }
        for (Symbol sym : st.getGlobalSymbols(target)) {
            if (sym.getAddress() != null) candidates.add(sym.getAddress());
        }
        FunctionIterator iter = session.program().getFunctionManager().getFunctions(true);
        while (iter.hasNext()) {
            Function func = iter.next();
            if (func.getName().equals(target)) candidates.add(func.getEntryPoint());
        }
        return candidates;
    }

    Address resolveAddress(String target) {
        if (session.program() == null || target == null || target.trim().isEmpty()) return null;
        Address explicit = parseAddress(target);
        if (explicit != null) return explicit;
        LinkedHashSet<Address> candidates = namedAddresses(target.trim());
        if (candidates.size() > 1) {
            throw new IllegalArgumentException("Ambiguous target '" + target + "' at "
                + candidates.stream().map(AddressCodec::format).toList()
                + "; use a 0x-prefixed address");
        }
        return candidates.isEmpty() ? null : candidates.iterator().next();
    }

    /** Inclusive range of instruction start addresses, restricted to mapped memory.
     * A one-sided range stays in the supplied endpoint's address space. */
    AddressSetView instructionRange(String startText, String endText) {
        Address start = startText == null ? null : resolveAddress(startText);
        Address end = endText == null ? null : resolveAddress(endText);
        if (startText != null && start == null) {
            throw new IllegalArgumentException("Invalid start address: " + startText);
        }
        if (endText != null && end == null) {
            throw new IllegalArgumentException("Invalid end address: " + endText);
        }
        if (start == null && end == null) return session.program().getMemory();
        if (start == null) start = end.getAddressSpace().getMinAddress();
        if (end == null) end = start.getAddressSpace().getMaxAddress();
        if (!start.getAddressSpace().equals(end.getAddressSpace())) {
            throw new IllegalArgumentException("Start and end must be in the same address space");
        }
        if (start.compareTo(end) > 0) {
            throw new IllegalArgumentException("Start address must not be after end address");
        }
        return new AddressSet(start, end).intersect(session.program().getMemory());
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

        Address primary = parseAddress(target);
        if (primary != null) {
            targets.add(primary);
        } else {
            targets.addAll(namedAddresses(target.trim()));
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
