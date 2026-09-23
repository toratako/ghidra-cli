package ghidracli.memory;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import ghidra.program.model.address.Address;
import ghidracli.protocol.JsonProtocol;
import ghidracli.query.AddressCodec;
import ghidracli.query.AddressResolver;
import ghidracli.session.ProgramSession;
import java.util.Arrays;

import static ghidracli.protocol.JsonProtocol.errorResult;
import static ghidracli.protocol.JsonProtocol.getArgString;

public final class MemoryCommands {
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

            // Read bytes
            byte[] bytes = new byte[size];
            JsonArray mappings = source.equals("original")
                ? MemorySources.readOriginal(session, baseAddr, bytes) : null;
            int bytesRead = mappings == null ? mem.getBytes(baseAddr, bytes) : size;

            // Build hex string
            StringBuilder hexStr = new StringBuilder();
            for (int i = 0; i < bytesRead; i++) {
                hexStr.append(String.format("%02x", bytes[i] & 0xFF));
            }

            JsonObject result = new JsonObject();
            result.addProperty("address", AddressCodec.format(baseAddr));
            result.addProperty("source", source);
            result.addProperty("size", bytesRead);
            result.addProperty("hex", hexStr.toString());
            if (mappings != null) {
                result.add("mappings", mappings);
                return result;
            }

            int pointerSize = session.program().getDefaultPointerSize();
            result.addProperty("pointer_size", pointerSize);
            result.addProperty("endian", mem.isBigEndian() ? "big" : "little");
            PointerValues pointerValues = new PointerValues(session);
            JsonArray pointers = new JsonArray();
            for (int i = 0; i <= bytesRead - pointerSize; i += pointerSize) {
                session.monitor().checkCancelled();
                Address pointerAddr = baseAddr.addNoWrap(i);
                JsonObject ptrObj = pointerValues.read(pointerAddr,
                    Arrays.copyOfRange(bytes, i, i + pointerSize));
                ptrObj.addProperty("offset", i);
                pointers.add(ptrObj);
            }

            result.add("pointers", pointers);
            return result;
        } catch (Exception e) {
            return errorResult("Failed to read memory: " + e.getMessage());
        }
    }
}
