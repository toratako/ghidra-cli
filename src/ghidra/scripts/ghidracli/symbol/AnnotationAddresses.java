package ghidracli.symbol;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSpace;
import ghidracli.query.AddressCodec;

/** Addresses that Ghidra can store without aliasing a different annotation target. */
final class AnnotationAddresses {
    private AnnotationAddresses() {}

    static boolean supports(AddressSpace space) {
        return space.isMemorySpace() || space.isExternalSpace() || space.isRegisterSpace()
            || space.isStackSpace() || space.isVariableSpace() || space.isHashSpace();
    }

    static Address parse(AddressFactory factory, String text) {
        Address address = AddressCodec.parse(factory, text);
        if (address == null) return null;
        AddressSpace space = address.getAddressSpace();
        // The persistent address map stores non-memory offsets in 32 bits,
        // sign-extending stack offsets on decode. Constant/unique addresses
        // instead share its invalid-address key and cannot identify annotations.
        long offset = address.getOffset();
        boolean exactOffset = space.isMemorySpace() || space.isHashSpace()
            || (space.isStackSpace() ? offset == (int) offset : (offset >>> 32) == 0);
        if (!supports(space) || !exactOffset) {
            throw new IllegalArgumentException("Address cannot be persisted without changing its identity: "
                + AddressCodec.format(address));
        }
        return address;
    }
}
