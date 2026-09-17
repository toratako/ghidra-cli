package ghidracli;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.SegmentedAddress;
import ghidra.program.model.address.SegmentedAddressSpace;
import java.math.BigInteger;
import java.util.regex.Pattern;

/** The CLI's explicit, round-trippable address syntax. */
final class AddressCodec {
    private static final Pattern EXPLICIT_PREFIX = Pattern.compile("(?:^|:)0[xX]");
    private static final Pattern OFFSET = Pattern.compile("0[xX][0-9a-fA-F]+(?:\\.[0-9a-fA-F]+)?");
    private static final Pattern HEX = Pattern.compile("0[xX][0-9a-fA-F]+");

    private AddressCodec() {}

    /** Includes malformed explicit addresses, which must never fall back to names. */
    static boolean isExplicit(String text) {
        return text != null && EXPLICIT_PREFIX.matcher(text.trim()).find();
    }

    /** Syntax-only check for inputs whose program/address factory is not available yet. */
    static boolean isValidSyntax(String text) {
        if (text == null) return false;
        String value = text.trim();
        if (isValidOffsetSyntax(value)) return true;
        int separator = value.indexOf(':');
        return separator > 0 && AddressSpace.isValidName(value.substring(0, separator))
            && isValidOffsetSyntax(value.substring(separator + 1));
    }

    private static boolean isValidOffsetSyntax(String value) {
        String[] components = value.split(":", -1);
        if (components.length == 1) {
            if (!OFFSET.matcher(components[0]).matches()) return false;
            String[] parts = components[0].substring(2).split("\\.", -1);
            return new BigInteger(parts[0], 16).bitLength() <= 64
                && (parts.length == 1 || new BigInteger(parts[1], 16).bitLength() <= 3);
        }
        if (components.length != 2) return false;
        for (String component : components) {
            if (!HEX.matcher(component).matches()
                    || new BigInteger(component.substring(2), 16).bitLength() > 16) return false;
        }
        return true;
    }

    /** Returns null for names; rejects invalid explicit addresses without another interpretation. */
    static Address parse(AddressFactory factory, String text) {
        if (factory == null || !isExplicit(text)) return null;
        if (!isValidSyntax(text)) throw invalid(text);

        String offset = text.trim();
        AddressSpace space = factory.getDefaultAddressSpace();
        int separator = offset.indexOf(':');
        AddressSpace namedSpace = separator > 0
            ? namedSpace(factory, offset.substring(0, separator)) : null;
        if (namedSpace != null) {
            space = namedSpace;
            offset = offset.substring(separator + 1);
        } else if (!startsWithPrefix(offset)) {
            throw invalid(text);
        }
        if (space == null) throw invalid(text);

        try {
            String[] components = offset.split(":", -1);
            if (components.length == 2) {
                if (!(space instanceof SegmentedAddressSpace)) throw invalid(text);
                int segment = Integer.parseInt(components[0].substring(2), 16);
                int segmentOffset = Integer.parseInt(components[1].substring(2), 16);
                return ((SegmentedAddressSpace) space).getAddress(segment, segmentOffset);
            }

            String[] parts = offset.substring(2).split("\\.", -1);
            BigInteger word = new BigInteger(parts[0], 16);
            if (word.bitLength() > 64
                    || (!space.hasSignedOffset() && word.bitLength() > space.getSize())) {
                throw invalid(text);
            }
            int unit = space.getAddressableUnitSize();
            BigInteger remainder = parts.length == 1 ? BigInteger.ZERO : new BigInteger(parts[1], 16);
            if (remainder.compareTo(BigInteger.valueOf(unit)) >= 0) throw invalid(text);
            if (space.hasSignedOffset() && word.bitLength() == 64) {
                word = BigInteger.valueOf(word.longValue());
            }
            BigInteger byteOffset = word.multiply(BigInteger.valueOf(unit)).add(remainder);
            if (byteOffset.bitLength() > 64
                    || byteOffset.compareTo(BigInteger.valueOf(Long.MIN_VALUE)) < 0) throw invalid(text);
            long validatedOffset = space.makeValidOffset(byteOffset.longValue());
            // In particular, OverlayAddressSpace.getAddress(long) may substitute
            // the underlying physical space when the offset is outside a block.
            Address address = space.getAddressInThisSpaceOnly(validatedOffset);
            if (!address.getAddressSpace().equals(space) || address.getOffset() != validatedOffset) {
                throw invalid(text);
            }
            return address;
        } catch (RuntimeException e) {
            throw invalid(text);
        }
    }

    /** Canonical endpoints use a registered space name before any colon. */
    static Address parseCanonical(AddressFactory factory, String text) {
        if (factory == null || text == null) return null;
        String value = text.trim();
        int separator = value.indexOf(':');
        if (separator >= 0 && namedSpace(factory, value.substring(0, separator)) == null) {
            throw invalid(text);
        }
        return parse(factory, text);
    }

    static String format(Address address) {
        if (address == null || Address.NO_ADDRESS.equals(address)) return null;
        AddressSpace space = address.getAddressSpace();
        String offset;
        if (address instanceof SegmentedAddress) {
            offset = "0x" + address.toString(false).replace(":", ":0x");
        } else {
            int unit = space.getAddressableUnitSize();
            long wordOffset = space.hasSignedOffset() ? Math.floorDiv(address.getOffset(), unit)
                : address.getAddressableWordOffset();
            String word = Long.toHexString(wordOffset);
            int width = Math.min(8, (space.getSize() + 3) / 4);
            offset = "0x" + "0".repeat(Math.max(0, width - word.length())) + word;
            long remainder = space.hasSignedOffset() ? Math.floorMod(address.getOffset(), unit)
                : Long.remainderUnsigned(address.getOffset(), unit);
            if (remainder != 0) offset += "." + Long.toHexString(remainder);
        }
        // A leading hexadecimal component can also be a legal address-space name.
        // Naming segmented outputs removes that ambiguity on their next input.
        return address instanceof SegmentedAddress || space.showSpaceName()
            || space.isOverlaySpace() || !space.isMemorySpace()
            ? space.getName() + ":" + offset : offset;
    }

    private static boolean startsWithPrefix(String value) {
        return value.startsWith("0x") || value.startsWith("0X");
    }

    private static AddressSpace namedSpace(AddressFactory factory, String name) {
        AddressSpace space = factory.getAddressSpace(name);
        if (space != null) return space;
        // Ghidra registers VARIABLE under the lookup key "join", although
        // symbol addresses and the space itself retain the name "VARIABLE".
        AddressSpace joined = factory.getAddressSpace("join");
        return joined != null && joined.getName().equals(name) ? joined : null;
    }

    private static IllegalArgumentException invalid(String text) {
        return new IllegalArgumentException("Invalid address: " + text
            + ". Use 0x-prefixed hexadecimal offsets (optionally space:0x...).");
    }
}
