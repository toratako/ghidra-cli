package ghidracli.query;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidracli.session.ProgramSession;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.concurrent.CancellationException;

public final class AddressResolver {
    private final ProgramSession session;

    public AddressResolver(ProgramSession session) {
        this.session = session;
    }

    public Address parseAddress(String addrStr) {
        return session.program() == null ? null
            : AddressCodec.parse(session.program().getAddressFactory(), addrStr);
    }

    public LinkedHashSet<Address> namedAddresses(String target) {
        checkCancelled();
        LinkedHashSet<Address> candidates = new LinkedHashSet<>();
        SymbolTable st = session.program().getSymbolTable();
        appendSymbols(st.getSymbols(target), null, candidates);
        for (Symbol symbol : st.getGlobalSymbols(target)) {
            checkCancelled();
            appendAddress(symbol.getAddress(), candidates);
        }
        // A symbol's own name may contain :: (for example a C++ template).
        // Every split can be the namespace boundary; compare the complete name.
        for (int separator = target.indexOf("::"); separator >= 0;
                separator = target.indexOf("::", separator + 2)) {
            checkCancelled();
            appendSymbols(st.getSymbols(target.substring(separator + 2)), target, candidates);
        }
        // Generated external names are absent from the name index, and the
        // function iterator below visits only local functions. Include both
        // external labels and functions before deciding that a name is unique.
        SymbolIterator externals = st.getExternalSymbols();
        while (externals.hasNext()) {
            checkCancelled();
            Symbol symbol = externals.next();
            if (symbol.getName().equals(target) || symbol.getName(true).equals(target)) {
                appendAddress(symbol.getAddress(), candidates);
            }
        }
        FunctionIterator iter = session.program().getFunctionManager().getFunctions(true);
        while (iter.hasNext()) {
            checkCancelled();
            Function func = iter.next();
            if (func.getName().equals(target) || func.getSymbol().getName(true).equals(target)) {
                candidates.add(func.getEntryPoint());
            }
        }
        return candidates;
    }

    private void appendSymbols(SymbolIterator syms, String qualifiedName, Set<Address> candidates) {
        while (syms.hasNext()) {
            checkCancelled();
            Symbol symbol = syms.next();
            if (qualifiedName == null || symbol.getName(true).equals(qualifiedName)) {
                appendAddress(symbol.getAddress(), candidates);
            }
        }
    }

    private static void appendAddress(Address address, Set<Address> candidates) {
        if (address != null && !Address.NO_ADDRESS.equals(address)) candidates.add(address);
    }

    private void checkCancelled() {
        if (session.monitor().isCancelled()) throw new CancellationException("Command cancelled");
    }

    public Address resolveAddress(String target) {
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
    public AddressSetView instructionRange(String startText, String endText) {
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
    public LinkedHashSet<Address> resolveXrefTargets(String target) {
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
                checkCancelled();
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
