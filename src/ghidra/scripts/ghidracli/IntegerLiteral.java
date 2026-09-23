package ghidracli;

import java.math.BigInteger;

/** Integer spelling shared by numeric operands; callers enforce their own ranges. */
final class IntegerLiteral {
    private IntegerLiteral() {}

    static BigInteger parse(String text) {
        if (!text.matches("[+-]?(?:0[xX][0-9a-fA-F]+|[0-9]+)"))
            throw new NumberFormatException("expected a decimal or 0x-prefixed integer: " + text);
        int signLength = text.startsWith("+") || text.startsWith("-") ? 1 : 0;
        if (text.startsWith("0x", signLength) || text.startsWith("0X", signLength))
            return new BigInteger(text.substring(0, signLength) + text.substring(signLength + 2), 16);
        return new BigInteger(text, 10);
    }
}
