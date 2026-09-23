package ghidracli.listing;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.PseudoDisassembler;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.task.TaskMonitor;
import ghidracli.query.AddressCodec;
import ghidracli.query.AddressResolver;
import ghidracli.query.ListQuery;
import ghidracli.session.ProgramSession;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

import static ghidracli.protocol.JsonProtocol.errorResult;
import static ghidracli.protocol.JsonProtocol.getArgString;
import static ghidracli.protocol.JsonProtocol.getNonnegativeIntArg;

/** Read-only adapter for Ghidra's Search For Address Tables detector. */
public final class AddressTableSearch {
    private final ProgramSession session;
    private final AddressResolver resolver;

    public AddressTableSearch(ProgramSession session, AddressResolver resolver) {
        this.session = session;
        this.resolver = resolver;
    }

    public JsonObject handleFindAddressTables(JsonObject args) throws Exception {
        Program program = session.program();
        if (program == null) return errorResult("No program loaded");
        int pointerSize = program.getDefaultPointerSize();
        // The native implementation reads only int/long values correctly for
        // ordinary byte-addressed pointers. Its special padded 24-bit handling
        // does not provide the same layout contract.
        if ((pointerSize != 4 && pointerSize != 8)
                || program.getAddressFactory().getDefaultAddressSpace().getAddressableUnitSize() != 1) {
            return errorResult("Native address-table search requires 4- or 8-byte pointers in byte-addressed memory");
        }
        int minimum = getNonnegativeIntArg(args, "min_entries", 3);
        if (minimum < 2) throw new IllegalArgumentException("min_entries must be at least 2");
        int defaultAlignment = PseudoDisassembler.hasLowBitCodeModeInAddrValues(program)
            ? 1 : program.getLanguage().getInstructionAlignment();
        // These are the native detector's accepted alignments. Avoid reporting
        // an input that Ghidra would silently normalize to a different value.
        if (defaultAlignment < 1 || defaultAlignment > 8) defaultAlignment = 1;
        int alignment = getNonnegativeIntArg(args, "alignment", defaultAlignment);
        if (alignment < 1 || alignment > 8) {
            throw new IllegalArgumentException("alignment must be an integer from 1 to 8");
        }
        AddressSetView requested = resolver.instructionRange(
            getArgString(args, "start"), getArgString(args, "end"));
        AddressSet scope = new AddressSet(requested).intersect(
            program.getMemory().getLoadedAndInitializedAddressSet());
        long limit = ListQuery.pageArgument(args, "limit");
        NativeDetector detector;
        try {
            detector = new NativeDetector();
        } catch (ClassNotFoundException | NoSuchMethodException unavailable) {
            return errorResult("Native address-table search is unavailable in this Ghidra installation: "
                + unavailable.getMessage());
        }

        JsonArray results = new JsonArray();
        AddressIterator addresses = scope.getAddresses(true);
        boolean complete = true;
        while (addresses.hasNext()) {
            session.monitor().checkCancelled();
            if (limit > 0 && results.size() >= limit) {
                complete = false;
                break;
            }
            Address start = addresses.next();
            if (start.getOffset() % alignment != 0) continue;
            if (start.getAddressSpace().getAddressableUnitSize() != 1) {
                throw new IllegalArgumentException("Native address-table search requires byte-addressed memory: "
                    + start.getAddressSpace().getName());
            }
            Object table = detector.find(program, start, session.monitor(), minimum, alignment);
            // getEntry returns a partial table on cancellation. Never publish it
            // as a successful candidate, even when a result limit has been met.
            session.monitor().checkCancelled();
            if (table == null) continue;
            int entries = ((Number) detector.entries.invoke(table)).intValue();
            int indexLength = ((Number) detector.indexLength.invoke(table)).intValue();
            long byteLength = (long) entries * pointerSize + indexLength;
            Address end = start.addNoWrap(byteLength - 1);
            Symbol symbol = program.getSymbolTable().getPrimarySymbol(start);
            String name = symbol == null ? "" : symbol.getName(true);
            JsonObject row = new JsonObject();
            row.addProperty("address", AddressCodec.format(start));
            row.addProperty("end", AddressCodec.format(end));
            row.addProperty("entry_count", entries);
            row.addProperty("byte_length", byteLength);
            if (!name.isEmpty()) row.addProperty("name", name);
            Address index = (Address) detector.indexAddress.invoke(table);
            if (index != null) {
                row.addProperty("index_address", AddressCodec.format(index));
                row.addProperty("index_length", indexLength);
            }
            results.add(row);
            // Match the native GUI search: a detected candidate consumes its
            // table and optional byte-index array. Scope bounds select starts,
            // not the extent read internally by getEntry.
            Address next = end.next();
            if (next == null) {
                addresses = scope.getAddresses(end, true);
                if (scope.contains(end) && addresses.hasNext()) addresses.next();
            } else {
                addresses = scope.getAddresses(next, true);
            }
        }
        session.monitor().checkCancelled();
        JsonObject result = new JsonObject();
        result.add("results", results);
        result.addProperty("count", results.size());
        result.addProperty("detector", "ghidra-address-table");
        result.addProperty("scope", "candidate-starts");
        JsonArray ranges = new JsonArray();
        for (AddressRange range : scope.getAddressRanges()) {
            session.monitor().checkCancelled();
            JsonObject row = new JsonObject();
            row.addProperty("start", AddressCodec.format(range.getMinAddress()));
            row.addProperty("end", AddressCodec.format(range.getMaxAddress()));
            ranges.add(row);
        }
        result.add("ranges", ranges);
        result.addProperty("pointer_size", pointerSize);
        result.addProperty("endian", program.getLanguage().isBigEndian() ? "big" : "little");
        result.addProperty("pointer_shift", program.getDataTypeManager().getDataOrganization().getPointerShift());
        result.addProperty("min_entries", minimum);
        result.addProperty("alignment", alignment);
        JsonObject scan = new JsonObject();
        scan.addProperty("complete", complete);
        if (!complete) scan.addProperty("stop_reason", "limit");
        result.add("scan", scan);
        return result;
    }

    /** Do not make a private Ghidra GUI package a hard OSGi import. */
    private static final class NativeDetector {
        final Method find;
        final Method entries;
        final Method indexAddress;
        final Method indexLength;

        NativeDetector() throws ClassNotFoundException, NoSuchMethodException {
            String prefix = "ghidra.app.plugin.core.disassembler.";
            Class<?> type = GhidraScript.class.getClassLoader().loadClass(prefix + "AddressTable");
            find = type.getMethod("getEntry", Program.class, Address.class, TaskMonitor.class,
                boolean.class, int.class, int.class, int.class, long.class,
                boolean.class, boolean.class, boolean.class);
            entries = type.getMethod("getNumberAddressEntries");
            indexAddress = type.getMethod("getTopIndexAddress");
            indexLength = type.getMethod("getIndexLength");
        }

        Object find(Program program, Address start, TaskMonitor monitor, int minimum, int alignment)
                throws Exception {
            try {
                // Same settings as AutoTableDisassemblerModel: existing listing
                // definitions are allowed, no inter-entry skip, no minimum
                // pointer value, native pointer shifts, optional index detection,
                // and no relocation-table requirement.
                return find.invoke(null, program, start, monitor, false, minimum, alignment,
                    0, 0L, true, true, false);
            } catch (InvocationTargetException failure) {
                Throwable cause = failure.getCause();
                if (cause instanceof Exception) throw (Exception) cause;
                if (cause instanceof Error) throw (Error) cause;
                throw failure;
            }
        }
    }
}
