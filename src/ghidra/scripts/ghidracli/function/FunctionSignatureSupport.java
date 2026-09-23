package ghidracli.function;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import ghidra.app.util.cparser.C.CParser;
import ghidra.app.util.cparser.C.CParserConstants;
import ghidra.app.util.cparser.C.Declaration;
import ghidra.app.util.cparser.C.ParseException;
import ghidra.app.util.cparser.C.Token;
import ghidra.app.util.cparser.C.TokenMgrError;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Enum;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.Union;
import ghidra.util.exception.CancelledException;
import ghidracli.protocol.JsonProtocol;
import ghidracli.query.IntegerLiteral;
import ghidracli.session.ProgramSession;
import ghidracli.types.SignatureTypes;
import java.io.StringReader;
import java.util.Set;

/** Parse one declaration off-Program, sharing exact type selection with --type edits. */
final class FunctionSignatureSupport {
    private static final Set<String> TYPE_QUALIFIERS = Set.of(
        "const", "__const", "__const__", "volatile", "__volatile", "__volatile__",
        "restrict", "__restrict", "__restrict__", "_Atomic");

    private FunctionSignatureSupport() {}

    static FunctionDefinitionDataType parse(ProgramSession session, String signature,
            JsonElement bindings, boolean callSite) throws CancelledException {
        if (signature == null || signature.isBlank()) {
            throw new IllegalArgumentException("signature must not be empty");
        }
        try (SignatureTypes types = new SignatureTypes(session)) {
            types.bind(bindings);
            CParser parser = new CParser(types, false, null);
            types.attach(parser);
            parser.setMonitor(session.monitor());
            validateTokens(session, parser, types, signature, callSite);
            parser.ReInit(new StringReader(signature));
            try {
                // Use the native declarator grammar, not TranslationUnit: the
                // latter accepts bodies/multiple declarations and can recover
                // from errors by returning an earlier successfully parsed type.
                Declaration specifiers = parser.DeclarationSpecifiers(new Declaration());
                Declaration declaration = parser.Declarator(specifiers, null);
                if (";".equals(parser.getToken(1).image)) parser.getNextToken();
                if (parser.getToken(1).kind != CParserConstants.EOF) {
                    throw invalid("expected one function declaration", parser.getToken(1));
                }
                if (!(declaration.getDataType() instanceof FunctionDefinitionDataType definition)) {
                    throw invalid("expected a function declaration", parser.getToken(0));
                }
                if (!parser.getParseMessages().isBlank()) {
                    throw invalid(parser.getParseMessages().trim(), parser.getToken(0));
                }
                validateCallbacks(parser);
                session.monitor().checkCancelled();
                // Detach from the scratch manager before closing it. Existing
                // dependencies keep their identities when cloned back.
                return (FunctionDefinitionDataType) definition.clone(session.program().getDataTypeManager());
            } catch (ParseException e) {
                Token token = e.currentToken != null && e.currentToken.next != null
                    ? e.currentToken.next : parser.getToken(1);
                if (token.kind == CParserConstants.IDENTIFIER && types.wasMissing(token.image)) {
                    throw SignatureTypes.unknown(token.image);
                }
                throw invalid(e.getMessage(), token);
            }
        } catch (TokenMgrError e) {
            throw new IllegalArgumentException("Invalid function signature: " + e.getMessage());
        }
    }

    private static void validateTokens(ProgramSession session, CParser parser, SignatureTypes types,
            String signature, boolean callSite) throws CancelledException {
        parser.ReInit(new StringReader(signature));
        Token previous = null;
        for (Token token = parser.getNextToken(); token.kind != CParserConstants.EOF;
                token = parser.getNextToken()) {
            session.monitor().checkCancelled();
            if (TYPE_QUALIFIERS.contains(token.image)) {
                throw invalid("Ghidra function signatures cannot preserve the C type qualifier '"
                    + token.image + "'", token);
            }
            switch (token.kind) {
                case CParserConstants.CDECL, CParserConstants.STDCALL, CParserConstants.FASTCALL,
                        CParserConstants.VECTORCALL, CParserConstants.RUSTCALL, CParserConstants.PASCALCALL ->
                    throw invalid(callSite ? "select the calling convention with --convention"
                        : "select the calling convention with function set-calling-convention", token);
                case CParserConstants.TYPEDEF ->
                    throw invalid("expected a function declaration, not a typedef", token);
                case CParserConstants.ATTRIBUTE, CParserConstants.DECLSPEC, CParserConstants.ALIGNAS,
                        CParserConstants.UNALIGNED, CParserConstants.PACKED, CParserConstants.PTR32,
                        CParserConstants.PTR64, CParserConstants.W64, CParserConstants.NEAR,
                        CParserConstants.FAR, CParserConstants.NORETURN, CParserConstants.STATIC,
                        CParserConstants.INLINE, CParserConstants.ASM, CParserConstants.EXTENSION ->
                    throw invalid("unsupported declaration modifier '" + token.image + "'", token);
                default -> { }
            }
            if ("{".equals(token.image) || "}".equals(token.image)) {
                throw invalid("expected a function declaration without a body or type definition", token);
            }
            if ("=".equals(token.image) || "&".equals(token.image)) {
                throw invalid("initializers and C++ references are not function signature types", token);
            }
            if ("[".equals(token.image)) {
                Token count = parser.getToken(1);
                if (!"]".equals(count.image)) {
                    // CParser substitutes zero for unknown constant expressions,
                    // silently turning an array parameter into a pointer.
                    if (!count.image.matches("(?:[0-9]+|0[xX][0-9a-fA-F]+)")
                            || !"]".equals(parser.getToken(2).image)) {
                        throw invalid("array dimensions must be integer literals or empty", count);
                    }
                    var size = IntegerLiteral.parse(count.image);
                    if (size.signum() <= 0 || size.bitLength() > 31) {
                        throw invalid("array dimension must be a positive int", count);
                    }
                }
            }
            if (previous != null && (previous.kind == CParserConstants.STRUCT
                    || previous.kind == CParserConstants.UNION || previous.kind == CParserConstants.ENUM)
                    && token.kind == CParserConstants.IDENTIFIER) {
                DataType type = types.lookup(token.image);
                if (type == null) throw SignatureTypes.unknown(token.image);
                boolean matches = switch (previous.kind) {
                    case CParserConstants.STRUCT -> type instanceof Structure;
                    case CParserConstants.UNION -> type instanceof Union;
                    default -> type instanceof Enum;
                };
                if (!matches) throw invalid("'" + token.image + "' is not a " + previous.image, token);
            }
            previous = token;
        }
    }

    private static void validateCallbacks(CParser parser) {
        for (DataType parsed : parser.getFunctions().values()) {
            if (!(parsed instanceof FunctionDefinition function)) continue;
            for (var parameter : function.getArguments()) {
                DataType type = parameter.getDataType();
                while (type instanceof Pointer pointer) type = pointer.getDataType();
                if (type instanceof FunctionDefinition callback && callback.getSourceArchive() == null
                        && callback.getName().startsWith("_func_")
                        && parameter.getName() != null && !parameter.getName().isEmpty()
                        && !parameter.getName().equals(callback.getName())
                        && !parser.getFunctions().containsValue(callback)) {
                    // Native CParser turns `int (value)` into an anonymous
                    // function pointer. Never apply that altered parameter type.
                    throw invalid("cannot safely parse parenthesized parameter '"
                        + parameter.getName() + "'", parser.getToken(0));
                }
            }
        }
    }

    private static JsonProtocol.CommandException invalid(String message, Token token) {
        JsonObject detail = new JsonObject();
        detail.addProperty("line", token.beginLine);
        detail.addProperty("column", token.beginColumn);
        return new JsonProtocol.CommandException("Invalid function signature: " + message, detail);
    }
}
