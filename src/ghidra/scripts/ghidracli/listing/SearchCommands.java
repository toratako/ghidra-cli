package ghidracli.listing;

import com.google.gson.JsonArray;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.datastruct.ListAccumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidracli.query.AddressCodec;
import ghidracli.query.AddressResolver;
import ghidracli.query.ListQuery;
import ghidracli.session.ProgramSession;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.Charset;
import java.nio.charset.CodingErrorAction;
import java.util.Locale;
import java.util.regex.PatternSyntaxException;

import static ghidracli.protocol.JsonProtocol.errorResult;
import static ghidracli.protocol.JsonProtocol.getArgBool;
import static ghidracli.protocol.JsonProtocol.getArgString;
import static ghidracli.protocol.JsonProtocol.getNonnegativeIntArg;

public final class SearchCommands {
    private final ProgramSession session;
    private final AddressResolver addressResolver;
    private final StringQueries stringQueries;

    public SearchCommands(ProgramSession session, AddressResolver addressResolver,
            StringQueries stringQueries) {
        this.session = session;
        this.addressResolver = addressResolver;
        this.stringQueries = stringQueries;
    }

    public JsonObject handleFindConstant(JsonObject args) throws Exception {
        if (session.program() == null) return errorResult("No program loaded");
        return ConstantSearch.find(session, addressResolver, args);
    }

    public JsonObject handleFindInstruction(JsonObject args) throws Exception {
        if (session.program() == null) return errorResult("No program loaded");
        String pattern = getArgString(args, "pattern");
        if (pattern == null || pattern.isEmpty()) return errorResult("Non-empty pattern required");
        boolean caseSensitive = getArgBool(args, "case_sensitive", false);
        int limit = getNonnegativeIntArg(args, "limit", 0);
        AddressSetView range = addressResolver.instructionRange(
            getArgString(args, "start"), getArgString(args, "end"));
        String needle = caseSensitive ? pattern : pattern.toLowerCase(Locale.ROOT);
        JsonArray results = new JsonArray();
        for (Instruction instruction : session.program().getListing().getInstructions(range, true)) {
            session.monitor().checkCancelled();
            Address address = instruction.getAddress();
            // Match start addresses, even if a listing iterator includes a
            // code unit that overlaps the lower boundary.
            if (!range.contains(address)) continue;
            String text = instruction.toString();
            String haystack = caseSensitive ? text : text.toLowerCase(Locale.ROOT);
            if (!haystack.contains(needle)) continue;
            JsonObject row = new JsonObject();
            row.addProperty("address", AddressCodec.format(address));
            row.addProperty("disasm", text);
            Function function = session.program().getFunctionManager().getFunctionContaining(address);
            if (function != null) row.addProperty("function", function.getName());
            results.add(row);
            if (limit > 0 && results.size() >= limit) break;
        }
        JsonObject result = new JsonObject();
        result.add("results", results);
        result.addProperty("count", results.size());
        return result;
    }

    public JsonObject handleFindString(JsonObject args) {
        if (session.program() == null) return errorResult("No program loaded");

        String pattern = getArgString(args, "pattern");
        try {
            JsonArray results = stringQueries.list(args, pattern);

            JsonObject result = new JsonObject();
            result.add("results", results);
            result.addProperty("count", results.size());
            return result;
        } catch (Exception e) {
            return errorResult("Failed to find strings: " + e.getMessage());
        }
    }

    public JsonObject handleFindText(JsonObject args) {
        if (session.program() == null) return errorResult("No program loaded");
        String text = getArgString(args, "text");
        if (text == null || text.isEmpty()) return errorResult("Non-empty text required");
        String encoding = getArgString(args, "encoding");
        if (encoding == null) encoding = "utf-8";
        try {
            long limit = ListQuery.pageArgument(args, "limit");
            Charset charset;
            try {
                charset = Charset.forName(encoding);
            } catch (IllegalArgumentException e) {
                return errorResult("Unsupported encoding: " + encoding);
            }
            ByteBuffer encoded = charset.newEncoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .encode(CharBuffer.wrap(text));
            byte[] bytes = new byte[encoded.remaining()];
            encoded.get(bytes);
            if (bytes.length == 0) return errorResult("Text encodes to an empty byte sequence");
            return searchMemory(bytes, limit, charset.name());
        } catch (CharacterCodingException e) {
            return errorResult("Text cannot be encoded as " + encoding);
        } catch (Exception e) {
            return errorResult("Failed to find text: " + e.getMessage());
        }
    }

    public JsonObject handleStringRefs(JsonObject args) {
        if (session.program() == null) return errorResult("No program loaded");

        String pattern = getArgString(args, "pattern");
        if (pattern == null || pattern.isEmpty()) return errorResult("String pattern required");
        String needle = pattern.toLowerCase(Locale.ROOT);

        try {
            Listing listing = session.program().getListing();
            ReferenceManager refMgr = session.program().getReferenceManager();
            FunctionManager fm = session.program().getFunctionManager();
            JsonArray results = new JsonArray();

            DataIterator dataIter = listing.getDefinedData(true);
            while (dataIter.hasNext()) {
                session.monitor().checkCancelled();
                Data data = dataIter.next();
                if (!data.hasStringValue()) continue;

                Object value = data.getValue();
                if (value == null) continue;
                String val = value.toString();
                if (!val.toLowerCase(Locale.ROOT).contains(needle)) continue;

                Address strAddr = data.getAddress();
                var destinations = refMgr.getReferenceDestinationIterator(
                    new AddressSet(data.getMinAddress(), data.getMaxAddress()), true);
                while (destinations.hasNext()) {
                    session.monitor().checkCancelled();
                    Address destination = destinations.next();
                    for (Reference ref : refMgr.getReferencesTo(destination)) {
                        session.monitor().checkCancelled();
                        JsonObject item = new JsonObject();
                        item.addProperty("string_address", AddressCodec.format(strAddr));
                        item.addProperty("string_value", val);
                        item.addProperty("from", AddressCodec.format(ref.getFromAddress()));
                        item.addProperty("to", AddressCodec.format(ref.getToAddress()));
                        item.addProperty("string_offset", ref.getToAddress().subtract(strAddr));
                        item.addProperty("ref_type", ref.getReferenceType().toString());
                        Function fn = fm.getFunctionContaining(ref.getFromAddress());
                        if (fn != null) {
                            item.addProperty("from_function", fn.getName());
                        } else {
                            item.add("from_function", JsonNull.INSTANCE);
                        }
                        results.add(item);
                    }
                }
            }

            JsonObject result = new JsonObject();
            result.add("results", results);
            result.addProperty("count", results.size());
            result.addProperty("pattern", pattern);
            return result;
        } catch (Exception e) {
            return errorResult("Failed to find string refs: " + e.getMessage());
        }
    }

    public JsonObject handleFindBytes(JsonObject args) {
        if (session.program() == null) return errorResult("No program loaded");

        String hexPattern = getArgString(args, "hex");
        if (hexPattern == null || hexPattern.isEmpty()) {
            return errorResult("No hex pattern provided");
        }

        try {
            long limit = ListQuery.pageArgument(args, "limit");
            String hexClean = hexPattern.replace("0x", "").replace(" ", "");
            if (hexClean.isEmpty() || (hexClean.length() % 2) != 0
                    || !hexClean.matches("[0-9a-fA-F]+")) {
                return errorResult("Hex pattern must contain non-empty complete byte pairs");
            }
            byte[] searchBytes = new byte[hexClean.length() / 2];
            for (int i = 0; i < searchBytes.length; i++) {
                searchBytes[i] = (byte) Integer.parseInt(hexClean.substring(i * 2, i * 2 + 2), 16);
            }

            return searchMemory(searchBytes, limit, null);
        } catch (Exception e) {
            return errorResult("Failed to find bytes: " + e.getMessage());
        }
    }

    public JsonObject handleFindBytesRegex(JsonObject args) {
        if (session.program() == null) return errorResult("No program loaded");
        String pattern = getArgString(args, "pattern");
        if (pattern == null || pattern.isEmpty()) return errorResult("Non-empty byte regex required");

        try {
            long limit = ListQuery.pageArgument(args, "limit");
            // Resolve the optional native API only for this command. Direct
            // imports would prevent the entire bridge from compiling on Ghidra
            // versions predating memsearch, and its classes became generic in
            // newer releases. Load through Ghidra's application class loader,
            // without making these packages hard OSGi bundle dependencies.
            ClassLoader loader = GhidraScript.class.getClassLoader();
            String prefix = "ghidra.features.base.memsearch.";
            Class<?> settingsClass = loader.loadClass(prefix + "gui.SearchSettings");
            Class<?> matcherClass = loader.loadClass(prefix + "matcher.RegExByteMatcher");
            Class<?> sourceClass = loader.loadClass(prefix + "bytesource.ProgramByteSource");
            Class<?> searcherClass = loader.loadClass(prefix + "searcher.MemorySearcher");
            Class<?> matchClass = loader.loadClass(prefix + "searcher.MemoryMatch");
            Object settings = settingsClass.getConstructor().newInstance();
            Object matcher = matcherClass.getConstructor(String.class, settingsClass)
                .newInstance(pattern, settings);
            Object source = sourceClass.getConstructor(Program.class).newInstance(session.program());
            Memory memory = session.program().getMemory();
            // The native accumulator and JSON arrays both have int-sized lengths;
            // do not narrow large valid wire limits by wrapping them to int.
            int nativeLimit = limit == 0 ? Integer.MAX_VALUE : (int) Math.min(limit, Integer.MAX_VALUE);
            Object searcher = searcherClass.getConstructor(
                loader.loadClass(prefix + "bytesource.AddressableByteSource"),
                loader.loadClass(prefix + "matcher.ByteMatcher"), AddressSetView.class, int.class)
                .newInstance(source, matcher, memory.getLoadedAndInitializedAddressSet(), nativeLimit);
            ListAccumulator<Object> matches = new ListAccumulator<>();
            session.monitor().checkCancelled();
            searcherClass.getMethod("findAll", Accumulator.class, TaskMonitor.class)
                .invoke(searcher, matches, session.monitor());
            // The native search returns partial results on cancellation. Never
            // report those as a successful, complete query.
            session.monitor().checkCancelled();
            JsonArray results = new JsonArray();
            Method getAddress = matchClass.getMethod("getAddress");
            Method getLength = matchClass.getMethod("getLength");
            for (Object match : matches) {
                session.monitor().checkCancelled();
                JsonObject row = new JsonObject();
                row.addProperty("address", AddressCodec.format((Address) getAddress.invoke(match)));
                row.addProperty("byte_length", (Number) getLength.invoke(match));
                results.add(row);
            }
            JsonObject result = new JsonObject();
            result.add("results", results);
            result.addProperty("count", results.size());
            return result;
        } catch (ClassNotFoundException | NoSuchMethodException e) {
            return errorResult("Native byte regex search is unavailable in this Ghidra installation: " + e.getMessage());
        } catch (Exception e) {
            Throwable cause = e instanceof InvocationTargetException ? e.getCause() : e;
            if (cause instanceof PatternSyntaxException) {
                PatternSyntaxException syntax = (PatternSyntaxException) cause;
                return errorResult("Invalid byte regex at index " + syntax.getIndex() + ": " + syntax.getDescription());
            }
            if (cause instanceof IllegalArgumentException && "Must provide at least 1 byte".equals(cause.getMessage())) {
                return errorResult("Byte regex produced a zero-length match; use a pattern that consumes at least one byte");
            }
            return errorResult("Failed to find byte regex: " + cause.getMessage());
        }
    }

    /** Shared exact-byte scanning, including overlapping matches and cancellation. */
    private JsonObject searchMemory(byte[] bytes, long limit, String encoding)
            throws CancelledException {
        Memory memory = session.program().getMemory();
        JsonArray results = new JsonArray();
        Address addr = memory.getMinAddress();
        while (addr != null && (limit == 0 || results.size() < limit)) {
            session.monitor().checkCancelled();
            Address found = memory.findBytes(addr, bytes, null, true, session.monitor());
            session.monitor().checkCancelled();
            if (found == null) break;
            JsonObject item = new JsonObject();
            item.addProperty("address", AddressCodec.format(found));
            if (encoding != null) {
                item.addProperty("byte_length", bytes.length);
                item.addProperty("encoding", encoding);
            }
            results.add(item);
            try {
                addr = found.addNoWrap(1);
            } catch (ghidra.program.model.address.AddressOverflowException e) {
                break;
            }
        }
        JsonObject result = new JsonObject();
        result.add("results", results);
        result.addProperty("count", results.size());
        return result;
    }

}
