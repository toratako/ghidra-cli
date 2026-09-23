package ghidracli.memory;

import com.google.gson.JsonObject;
import ghidra.app.util.PseudoDisassembler;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.ByteMemBufferImpl;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.exception.CancelledException;
import ghidracli.query.AddressCodec;
import ghidracli.session.ProgramSession;

/** Native pointer decoding and exact database metadata, without defining code or data. */
public final class PointerValues {
    private final ProgramSession session;

    public PointerValues(ProgramSession session) {
        this.session = session;
    }

    public JsonObject read(Address address) throws MemoryAccessException, CancelledException {
        return read(address, session.program().getDefaultPointerSize());
    }

    public JsonObject read(Address address, int width)
            throws MemoryAccessException, CancelledException {
        if (width < 1 || width > 8) {
            throw new IllegalArgumentException("Pointer width must be between 1 and 8 bytes");
        }
        session.monitor().checkCancelled();
        byte[] bytes = new byte[width];
        if (session.program().getMemory().getBytes(address, bytes) != width) {
            throw new MemoryAccessException("Incomplete pointer at " + AddressCodec.format(address));
        }
        return read(address, bytes);
    }

    JsonObject read(Address address, byte[] bytes)
            throws MemoryAccessException, CancelledException {
        session.monitor().checkCancelled();
        var memory = session.program().getMemory();
        ByteMemBufferImpl buffer = new ByteMemBufferImpl(memory, address, bytes, memory.isBigEndian());
        // Keep Ghidra's unsigned, segmented, addressable-word and overlay interpretation.
        Address target = PointerDataType.getAddressValue(buffer, bytes.length, address.getAddressSpace());
        JsonObject result = new JsonObject();
        result.addProperty("address", AddressCodec.format(address));
        result.addProperty("value", String.format("0x%0" + (bytes.length * 2) + "x",
            buffer.getBigInteger(0, bytes.length, false)));
        for (var field : describeTarget(target).entrySet()) {
            result.add(field.getKey(), field.getValue());
        }
        return result;
    }

    /** Describes an already decoded address, for example an explicit relative table entry. */
    public JsonObject describeTarget(Address target) throws CancelledException {
        session.monitor().checkCancelled();
        var program = session.program();
        JsonObject result = new JsonObject();
        result.addProperty("target_address", AddressCodec.format(target));
        result.addProperty("mapped", target == null ? null : program.getMemory().contains(target));

        Address codeAddress = target == null ? null
            : PseudoDisassembler.getNormalizedDisassemblyAddress(program, target);
        // An overlay boundary must not turn a Thumb target into a physical-space function.
        if (codeAddress != null && !codeAddress.getAddressSpace().equals(target.getAddressSpace())) {
            codeAddress = null;
        }
        result.addProperty("code_address", AddressCodec.format(codeAddress));

        Symbol symbol = target == null ? null : program.getSymbolTable().getPrimarySymbol(target);
        result.addProperty("symbol", symbol == null ? null : symbol.getName(true));
        Function function = codeAddress == null ? null
            : program.getFunctionManager().getFunctionAt(codeAddress);
        result.addProperty("function", function == null ? null : function.getName(true));
        result.addProperty("function_address", function == null ? null
            : AddressCodec.format(function.getEntryPoint()));
        result.add("thunk_target", function != null && function.isThunk()
            ? functionIdentity(function.getThunkedFunction(false)) : null);
        result.add("thunk_final_target", function != null && function.isThunk()
            ? functionIdentity(function.getThunkedFunction(true)) : null);
        return result;
    }

    private JsonObject functionIdentity(Function function) {
        if (function == null) return null;
        JsonObject result = new JsonObject();
        result.addProperty("address", AddressCodec.format(function.getEntryPoint()));
        result.addProperty("name", function.getName(true));
        return result;
    }
}
