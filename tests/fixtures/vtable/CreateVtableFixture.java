import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;

/** Explicit layouts exercise decoding without analyzer-created functions or data. */
public class CreateVtableFixture extends GhidraScript {
    private int pointerSize;

    private void pointer(long location, long value) throws Exception {
        if (pointerSize == 4) currentProgram.getMemory().setInt(toAddr(location), (int) value);
        else currentProgram.getMemory().setLong(toAddr(location), value);
    }

    private void scalar(long location, long value) throws Exception {
        currentProgram.getMemory().setInt(toAddr(location), (int) value);
    }

    private Function function(String name, long location) throws Exception {
        return currentProgram.getFunctionManager().createFunction(name, toAddr(location),
            new AddressSet(toAddr(location), toAddr(location + 3)), SourceType.USER_DEFINED);
    }

    public void run() throws Exception {
        pointerSize = currentProgram.getDefaultPointerSize();
        var memory = currentProgram.getMemory();
        var code = memory.createInitializedBlock("targets", toAddr(0x2000), 0x80,
            (byte) 0, monitor, false);
        code.setExecute(true);
        memory.createInitializedBlock("negative_target", toAddr(0x800), 4,
            (byte) 0, monitor, false).setExecute(true);
        var thumb = currentProgram.getRegister("TMode");
        int modeBit = thumb == null ? 0 : 1;
        if (thumb != null) {
            currentProgram.getProgramContext().setValue(thumb, toAddr(0x2000),
                toAddr(0x207f), java.math.BigInteger.ONE);
            currentProgram.getProgramContext().setValue(thumb, toAddr(0x800),
                toAddr(0x803), java.math.BigInteger.ONE);
        }
        var target = function("virtual_target", 0x2000);
        var thunk = function("virtual_thunk", 0x2020);
        thunk.setThunkedFunction(target);
        function("negative_target", 0x800);
        createLabel(toAddr(0x2040), "undefined_target", true, SourceType.USER_DEFINED);
        createLabel(toAddr(0x1200), "fixture_typeinfo", true, SourceType.USER_DEFINED);
        createLabel(toAddr(0x1220), "fixture_class_descriptor", true, SourceType.USER_DEFINED);
        createLabel(toAddr(0x1020), "absolute_address_point", true, SourceType.USER_DEFINED);

        // Secondary Itanium address point, null slot, mapped nonfunction,
        // unmapped target and thunk: none is an inferred table terminator.
        pointer(0x1020 - 2 * pointerSize, -16);
        pointer(0x1020 - pointerSize, 0x1200);
        long[] entries = {0x2000 + modeBit, 0, 0x2040, 0x9000, 0x2020 + modeBit};
        for (int i = 0; i < entries.length; i++) pointer(0x1020 + i * pointerSize, entries[i]);
        pointer(0x10a0, 0x2000 + modeBit); // RTTI-disabled table: both header words zero.

        // MSVC Complete Object Locator. 64-bit fields are image-relative,
        // including pSelf; 32-bit fields are absolute pointers.
        pointer(0x1120 - pointerSize, 0x1240);
        pointer(0x1120, 0x2000 + modeBit);
        pointer(0x1120 + pointerSize, 0x2020 + modeBit);
        scalar(0x1240, pointerSize == 8 ? 1 : 0);
        scalar(0x1244, 16);
        scalar(0x1248, 4);
        long base = pointerSize == 8 ? currentProgram.getImageBase().getOffset() : 0;
        scalar(0x124c, 0x1200 - base);
        scalar(0x1250, 0x1220 - base);
        if (pointerSize == 8) scalar(0x1254, 0x1240 - base);

        // Readable bytes are not sufficient evidence of a supported locator.
        byte[] locator = new byte[pointerSize == 8 ? 24 : 20];
        memory.getBytes(toAddr(0x1240), locator);
        memory.setBytes(toAddr(0x1280), locator);
        scalar(0x1280, 99);
        pointer(0x1140 - pointerSize, 0x1280);
        pointer(0x1140, 0x2000 + modeBit);
        memory.setBytes(toAddr(0x12a0), locator); // pSelf still points to 0x1240.
        pointer(0x1160 - pointerSize, 0x12a0);
        pointer(0x1160, 0x2000 + modeBit);

        // LLVM relative layout: ALL slot displacements are relative to the
        // address point, even the second slot; RTTI first resolves a proxy.
        scalar(0x1198, -24);
        scalar(0x119c, 0x1260 - 0x11a0);
        scalar(0x11a0, 0x800 - 0x11a0);
        scalar(0x11a4, 0x2000 - 0x11a0);
        scalar(0x11a8, 0);
        scalar(0x11ac, 0x9000 - 0x11a0);
        pointer(0x1260, 0x1200);
        scalar(0x11c0, Integer.MIN_VALUE); // Address-point addition must not wrap.
    }
}
