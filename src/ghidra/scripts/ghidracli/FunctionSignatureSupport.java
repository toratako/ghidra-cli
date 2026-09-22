package ghidracli;

import ghidra.app.util.parser.FunctionSignatureParser;
import ghidra.app.util.cparser.C.ParseException;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.listing.FunctionSignature;
import ghidra.util.exception.CancelledException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Headless signature parsing shared by function and call-site edits. */
final class FunctionSignatureSupport {
    private static final Pattern C_TYPE_QUALIFIER =
        Pattern.compile("\\b(?:const|volatile|restrict|_Atomic)\\b");
    private static final Pattern ADJACENT_POINTER_RETURN_NAME =
        Pattern.compile("^([^()]*\\*)([A-Za-z_][A-Za-z_0-9]*\\s*\\()");

    private FunctionSignatureSupport() {}

    static FunctionDefinitionDataType parse(ProgramSession session, FunctionSignature original,
            String signature) throws ParseException, CancelledException {
        if (signature == null || signature.isBlank()) {
            throw new IllegalArgumentException("signature must not be empty");
        }
        // Ghidra function datatypes cannot retain C type qualifiers. Reject
        // before parsing: a trailing qualifier can otherwise become a name.
        Matcher qualifier = C_TYPE_QUALIFIER.matcher(signature);
        if (qualifier.find()) {
            throw new IllegalArgumentException("Ghidra function signatures cannot preserve the C type qualifier '"
                + qualifier.group() + "' at character " + (qualifier.start() + 1));
        }
        // The native parser separates the return type and function name on
        // whitespace. Preserve the pointer depth while accepting Entry **lookup.
        String prepared = ADJACENT_POINTER_RETURN_NAME.matcher(signature).replaceFirst("$1 $2");
        FunctionSignatureParser parser =
            new FunctionSignatureParser(session.program().getDataTypeManager(), null);
        FunctionDefinitionDataType definition = parser.parse(original, prepared);
        if (definition == null) throw new IllegalArgumentException("Failed to parse signature: " + signature);
        return definition;
    }
}
