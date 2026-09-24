package ghidracli.memory;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.MemoryBlock;
import ghidracli.protocol.JsonProtocol;
import ghidracli.query.AddressCodec;
import ghidracli.query.AddressResolver;
import ghidracli.session.ProgramSession;
import java.util.Arrays;

import static ghidracli.protocol.JsonProtocol.errorResult;
import static ghidracli.protocol.JsonProtocol.getArgString;

public final class MemoryCommands {
    private static final int READ_CHUNK_SIZE = 16 * 1024;
    private static final char[] HEX_DIGITS = "0123456789abcdef".toCharArray();

    private final ProgramSession session;
    private final AddressResolver addressResolver;

    public MemoryCommands(ProgramSession session, AddressResolver addressResolver) {
        this.session = session;
        this.addressResolver = addressResolver;
    }

    public JsonObject handleMemoryWrite(JsonObject args) {
        if (session.program() == null) return errorResult("No program loaded");

        String addressStr = getArgString(args, "address");
        String hexData = getArgString(args, "hex");
        if (addressStr == null || hexData == null) {
            return errorResult("Address and hex data required");
        }

        try {
            Address addr = addressResolver.resolveAddress(addressStr);
            if (addr == null) return errorResult("Invalid address: " + addressStr);

            String hexClean = hexData.replace("0x", "").replace(" ", "");
            if (hexClean.isEmpty() || (hexClean.length() % 2) != 0
                    || !hexClean.matches("[0-9a-fA-F]+")) {
                return errorResult("Hex data must contain complete byte pairs (two hex digits per byte); "
                    + "provide non-empty, even-length hex data");
            }
            byte[] patchData = new byte[hexClean.length() / 2];
            for (int i = 0; i < patchData.length; i++) {
                patchData[i] = (byte) Integer.parseInt(hexClean.substring(i * 2, i * 2 + 2), 16);
            }

            MemoryPatch.write(session, addr, patchData);

            JsonObject result = new JsonObject();
            result.addProperty("status", "patched");
            result.addProperty("address", AddressCodec.format(addr));
            result.addProperty("bytes", patchData.length);
            return result;
        } catch (Exception e) {
            return errorResult("Failed to patch bytes: " + e.getMessage());
        }
    }

    public JsonObject handleReadMemory(JsonObject args) {
        if (session.program() == null) return errorResult("No program loaded");
        String addrStr = getArgString(args, "address");
        if (addrStr == null) return errorResult("Address required");

        try {
            int size = JsonProtocol.getNonnegativeIntArg(args, "size", 200);
            String source = getArgString(args, "source");
            if (source == null) source = "memory";
            if (!source.equals("memory") && !source.equals("original")) {
                return errorResult("source must be memory or original");
            }
            session.monitor().checkCancelled();
            ghidra.program.model.mem.Memory mem = session.program().getMemory();

            Address baseAddr = addressResolver.resolveAddress(addrStr);
            if (baseAddr == null) {
                return errorResult("Invalid address: " + addrStr);
            }

            if (source.equals("original")) {
                MemorySources.OriginalRead original = MemorySources.readOriginal(session, baseAddr, size);
                JsonObject result = new JsonObject();
                result.addProperty("address", AddressCodec.format(baseAddr));
                result.addProperty("source", source);
                result.addProperty("size", size);
                result.addProperty("hex", original.hex());
                result.add("mappings", original.mappings());
                return result;
            }

            int pointerSize = session.program().getDefaultPointerSize();
            int chunkSize = Math.max(pointerSize,
                READ_CHUNK_SIZE / pointerSize * pointerSize);
            byte[] bytes = new byte[chunkSize];
            StringBuilder hexStr = new StringBuilder();
            PointerValues pointerValues = new PointerValues(session);
            JsonArray pointers = new JsonArray();
            int bytesRead = 0;
            while (bytesRead < size) {
                session.monitor().checkCancelled();
                Address current;
                try {
                    current = baseAddr.addNoWrap(bytesRead);
                } catch (ghidra.program.model.address.AddressOverflowException e) {
                    // A read that reaches the end of an address space is a partial read.
                    if (bytesRead == 0) throw e;
                    break;
                }
                // Native getBytes stops at a missing or uninitialized block after
                // a readable prefix. A fresh chunk at that boundary would throw.
                if (bytesRead > 0) {
                    MemoryBlock block = mem.getBlock(current);
                    if (block == null || (!block.isInitialized() && !block.isMapped())) break;
                }
                int requested = Math.min(bytes.length, size - bytesRead);
                int read = mem.getBytes(current, bytes, 0, requested);
                appendHex(hexStr, bytes, read);
                for (int i = 0; i <= read - pointerSize; i += pointerSize) {
                    session.monitor().checkCancelled();
                    Address pointerAddr = current.addNoWrap(i);
                    JsonObject ptrObj = pointerValues.read(pointerAddr,
                        Arrays.copyOfRange(bytes, i, i + pointerSize));
                    ptrObj.addProperty("offset", bytesRead + i);
                    pointers.add(ptrObj);
                }
                bytesRead += read;
                if (read < requested) break;
            }

            JsonObject result = new JsonObject();
            result.addProperty("address", AddressCodec.format(baseAddr));
            result.addProperty("source", source);
            result.addProperty("size", bytesRead);
            result.addProperty("hex", hexStr.toString());
            result.addProperty("pointer_size", pointerSize);
            result.addProperty("endian", mem.isBigEndian() ? "big" : "little");
            result.add("pointers", pointers);
            return result;
        } catch (Exception e) {
            return errorResult("Failed to read memory: " + e.getMessage());
        }
    }

    static void appendHex(StringBuilder hex, byte[] bytes, int length) {
        if ((long) hex.length() + (long) length * 2 > Integer.MAX_VALUE - 8) {
            throw new IllegalArgumentException("Requested memory range is too large for a hex result");
        }
        for (int i = 0; i < length; i++) {
            int value = bytes[i] & 0xff;
            hex.append(HEX_DIGITS[value >>> 4]).append(HEX_DIGITS[value & 0xf]);
        }
    }
}
