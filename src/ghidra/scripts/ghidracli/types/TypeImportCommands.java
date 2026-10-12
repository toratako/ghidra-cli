package ghidracli.types;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import ghidra.app.util.cparser.C.CParser;
import ghidra.app.util.cparser.C.CParserConstants;
import ghidra.app.util.cparser.C.ParseException;
import ghidra.app.util.cparser.C.Token;
import ghidra.app.util.cparser.C.TokenMgrError;
import ghidra.program.database.data.DataTypeUtilities;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.StandAloneDataTypeManager;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.Union;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidracli.session.ProgramSession;
import java.io.StringReader;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static ghidracli.protocol.JsonProtocol.errorResult;
import static ghidracli.protocol.JsonProtocol.getArgString;

public final class TypeImportCommands {
    private final ProgramSession session;

    public TypeImportCommands(ProgramSession session) {
        this.session = session;
    }

    public JsonObject handleTypeImportC(JsonObject args) {
        if (session.program() == null) return errorResult("No program loaded");

        String code = getArgString(args, "code");
        if (code == null || code.trim().isEmpty()) {
            return errorResult("C code required");
        }

        String categoryPath = getArgString(args, "category");

        DataTypeManager dtm = session.program().getDataTypeManager();
        try (ImportTypes parsedManager = new ImportTypes(dtm)) {

            String processedCode = code.trim();
            if (!processedCode.endsWith(";")) {
                processedCode += ";";
            }

            // Parse without changing the Program, retaining existing references'
            // source identities until the definitions are staged and relocated.
            CParser parser = new CParser(parsedManager, false,
                new DataTypeManager[] { dtm });
            parser.setMonitor(session.monitor());
            parsedManager.parse(parser, processedCode);
            String parseMessages = parser.getParseMessages();

            Set<String> definedNames = new HashSet<>();
            definedNames.addAll(parser.getComposites().keySet());
            definedNames.addAll(parser.getEnums().keySet());
            definedNames.addAll(parser.getTypes().keySet());
            definedNames.addAll(parser.getFunctions().keySet());

            Set<DataType> parsedTypes = Collections.newSetFromMap(new IdentityHashMap<>());
            parsedTypes.addAll(parser.getComposites().values());
            parsedTypes.addAll(parser.getEnums().values());
            parsedTypes.addAll(parser.getTypes().values());
            parsedTypes.addAll(parser.getFunctions().values());

            // C tag and typedef namespaces can name distinct definitions at the
            // same Ghidra path. Resolving either with replacement would discard
            // the other and redirect its users to a different kind of type.
            Map<String, DataType> definitionsByPath = new HashMap<>();
            for (DataType type : parsedTypes) {
                if (definitionsByPath.putIfAbsent(type.getPathName(), type) != null) {
                    throw new IllegalArgumentException(
                        "C definitions share the same type path: " + type.getPathName());
                }
            }

            CategoryPath lookupPath = CategoryPath.ROOT;
            if (categoryPath != null) {
                String normalizedPath = categoryPath.startsWith("/")
                    ? categoryPath : "/" + categoryPath;
                lookupPath = new CategoryPath(normalizedPath);
            }
            Map<String, CategoryPath> definitionPaths = new HashMap<>();
            Set<String> visiblePaths = new HashSet<>();
            for (DataType dt : parsedTypes) {
                if (isUserFacingDataType(dt)) visiblePaths.add(dt.getPathName());
                for (DataType contained : DataTypeUtilities.getContainedDataTypes(dt)) {
                    if (!isDefinition(contained)) continue;
                    boolean declared = parsedTypes.contains(contained)
                        || contained.getSourceArchive() == null
                        || (contained instanceof FunctionDefinition
                            && definedNames.contains(contained.getName()));
                    if (!declared) continue;
                    CategoryPath destination = contained.getCategoryPath();
                    if (categoryPath != null) {
                        destination = isUserFacingDataType(contained)
                            ? lookupPath : new CategoryPath(lookupPath, "functions");
                    }
                    definitionPaths.put(contained.getPathName(), destination);
                }
            }

            Set<DataType> stagedTypes = new HashSet<>();
            Set<DataType> visibleTypes = new HashSet<>();
            Set<String> importedPaths = new HashSet<>();
            // Only the temporary manager needs a transaction here; ProgramSession
            // continues to own the live Program transaction and saving.
            int stagingTransaction = parsedManager.startTransaction("Stage C definitions");
            try {
                DataTypeConflictHandler stagingHandler = new DataTypeConflictHandler() {
                    @Override
                    public ConflictResult resolveConflict(DataType added, DataType existing) {
                        return added.getSourceArchive() == null
                            ? ConflictResult.REPLACE_EXISTING : ConflictResult.USE_EXISTING;
                    }

                    @Override
                    public boolean shouldUpdate(DataType source, DataType local) {
                        return source.getSourceArchive() == null;
                    }

                    @Override
                    public DataTypeConflictHandler getSubsequentHandler() {
                        return this;
                    }
                };
                for (DataType dt : parsedTypes) {
                    session.monitor().checkCancelled();
                    parsedManager.resolve(dt, stagingHandler);
                }
                // Resolve the entire graph before relocation. Equivalent typedefs
                // can reference live definitions, and anonymous members are absent
                // from the parser's definition maps.
                Map<DataType, CategoryPath> destinations = new HashMap<>();
                for (Map.Entry<String, CategoryPath> entry : definitionPaths.entrySet()) {
                    DataType staged = parsedManager.getDataType(entry.getKey());
                    if (staged == null) {
                        throw new IllegalStateException("C definition was not staged: " + entry.getKey());
                    }
                    destinations.put(staged, entry.getValue());
                }
                for (Map.Entry<DataType, CategoryPath> entry : destinations.entrySet()) {
                    DataType staged = entry.getKey();
                    parsedManager.disassociate(staged);
                    String name = staged.getName();
                    parsedManager.createCategory(entry.getValue()).moveDataType(
                        staged, DataTypeConflictHandler.REPLACE_HANDLER);
                    importedPaths.add(parsedManager.getDataType(entry.getValue(), name).getPathName());
                }
                for (DataType dt : parsedTypes) {
                    CategoryPath path = definitionPaths.getOrDefault(dt.getPathName(), dt.getCategoryPath());
                    DataType staged = parsedManager.getDataType(path, dt.getName());
                    if (staged == null) {
                        throw new IllegalStateException("C definition missing after staging: " + dt.getName());
                    }
                    stagedTypes.add(staged);
                    if (visiblePaths.contains(dt.getPathName())) visibleTypes.add(staged);
                }
            } finally {
                parsedManager.endTransaction(stagingTransaction, true);
            }

            // Referenced types outside this import retain their live definitions,
            // even if staging a declaration affected a shared dependency there.
            DataTypeConflictHandler handler = new DataTypeConflictHandler() {
                @Override
                public ConflictResult resolveConflict(DataType added, DataType existing) {
                    return importedPaths.contains(added.getPathName())
                        ? ConflictResult.REPLACE_EXISTING : ConflictResult.USE_EXISTING;
                }

                @Override
                public boolean shouldUpdate(DataType source, DataType local) {
                    return importedPaths.contains(source.getPathName());
                }

                @Override
                public DataTypeConflictHandler getSubsequentHandler() {
                    return this;
                }
            };
            Set<DataType> importedTypes = new HashSet<>();
            for (DataType dt : stagedTypes) {
                session.monitor().checkCancelled();
                DataType imported = dtm.resolve(dt, handler);
                if (visibleTypes.contains(dt)) importedTypes.add(imported);
            }

            JsonArray typesArray = new JsonArray();
            for (String name : definedNames) {
                DataType best = findBestParsedDataType(name, importedTypes, lookupPath);
                if (best != null) {
                    JsonObject typeInfo = new JsonObject();
                    typeInfo.addProperty("name", best.getName());
                    typeInfo.addProperty("path", best.getPathName());
                    typeInfo.addProperty("size", best.getLength());
                    typeInfo.addProperty("category",
                        best.getCategoryPath().toString());
                    typesArray.add(typeInfo);
                }
            }

            JsonObject response = new JsonObject();
            response.addProperty("status", "imported");
            response.add("types", typesArray);
            if (parseMessages != null && !parseMessages.trim().isEmpty()) {
                response.addProperty("messages", parseMessages.trim());
            }
            return response;
        } catch (ParseException | TokenMgrError failure) {
            return errorResult("C parse error: " + failure.getMessage());
        } catch (Exception e) {
            return errorResult("Failed to import C types: " + e.getMessage(), e);
        }
    }

    /** Keep CParser's external lookups exact without replacing its local declarations. */
    private final class ImportTypes extends StandAloneDataTypeManager {
        private final TypeResolver resolver = new TypeResolver(session);
        private TagDeclarations tags;
        private CParser parser;
        private RuntimeException lookupFailure;

        ImportTypes(DataTypeManager programTypes) {
            super("C import", programTypes.getDataOrganization());
        }

        void parse(CParser parser, String code) throws ParseException, CancelledException {
            tags = tagDeclarations(code, session.monitor());
            this.parser = parser;
            try {
                parser.parse(code);
            } catch (ParseException failure) {
                // Native CParser wraps runtime lookup failures without retaining
                // their message or cause. Preserve the ambiguity candidates.
                if (lookupFailure != null) throw lookupFailure;
                throw failure;
            } finally {
                this.parser = null;
            }
        }

        @Override
        public void findDataTypes(String name, List<DataType> results) {
            super.findDataTypes(name, results);
            if (parser == null || !results.isEmpty() || !name.matches("[A-Za-z_$][A-Za-z_$0-9]*")
                    || tags.defined.contains(name)) return;
            Token previous = parser.getToken(0);
            Token next = parser.getToken(1);
            // Native parsing probes a field/parameter/typedef name after its type.
            if (previous.kind == CParserConstants.IDENTIFIER && name.equals(next.image)
                    && !name.equals(previous.image)) return;
            try {
                DataType existing = resolver.resolveRegisteredDataType(name);
                if (existing != null) {
                    Integer kind = tags.kinds.get(name);
                    if (kind != null && !(kind == CParserConstants.STRUCT && existing instanceof Structure)
                            && !(kind == CParserConstants.UNION && existing instanceof Union)
                            && !(kind == CParserConstants.ENUM && existing instanceof ghidra.program.model.data.Enum))
                        throw new IllegalArgumentException("C tag kind does not match registered type: "
                            + existing.getPathName());
                    results.add(existing.clone(this));
                }
            } catch (RuntimeException failure) {
                lookupFailure = failure;
                throw failure;
            }
        }
    }

    private static final class TagDeclarations {
        final Set<String> defined = new HashSet<>();
        final Map<String, Integer> kinds = new HashMap<>();
    }

    /** Tag bodies shadow external names throughout their declaration, including forward uses. */
    private static TagDeclarations tagDeclarations(String code, TaskMonitor monitor) throws CancelledException {
        TagDeclarations tags = new TagDeclarations();
        CParser tokens = new CParser(new StringReader(code));
        for (Token token = tokens.getNextToken(); token.kind != CParserConstants.EOF;
                token = tokens.getNextToken()) {
            monitor.checkCancelled();
            if (token.kind != CParserConstants.STRUCT && token.kind != CParserConstants.UNION
                    && token.kind != CParserConstants.ENUM) continue;
            int kind = token.kind;
            token = tokens.getNextToken();
            // Attributes and declspecs may precede the tag name. Ignore their
            // balanced arguments so identifiers there cannot become tag names.
            while (token.kind != CParserConstants.IDENTIFIER && token.kind != CParserConstants.EOF
                    && !"{".equals(token.image) && !";".equals(token.image)) {
                monitor.checkCancelled();
                if ("(".equals(token.image)) {
                    int depth = 1;
                    while (depth > 0) {
                        monitor.checkCancelled();
                        token = tokens.getNextToken();
                        if (token.kind == CParserConstants.EOF) return tags;
                        if ("(".equals(token.image)) depth++;
                        if (")".equals(token.image)) depth--;
                    }
                }
                token = tokens.getNextToken();
            }
            if (token.kind != CParserConstants.IDENTIFIER) continue;
            String name = token.image;
            Integer previousKind = tags.kinds.putIfAbsent(name, kind);
            if (previousKind != null && previousKind != kind)
                throw new IllegalArgumentException("C tag name has conflicting kinds: " + name);
            token = tokens.getNextToken();
            // Native CParser accepts a parent struct or an enum's underlying
            // type after ':'. Neither is another definition's tag name.
            if (":".equals(token.image)) {
                do {
                    monitor.checkCancelled();
                    token = tokens.getNextToken();
                } while (token.kind != CParserConstants.EOF && !"{".equals(token.image)
                    && !";".equals(token.image) && !",".equals(token.image)
                    && !")".equals(token.image));
            }
            if ("{".equals(token.image)) tags.defined.add(name);
            if (token.kind == CParserConstants.EOF) break;
        }
        return tags;
    }

    private boolean isDefinition(DataType dt) {
        return dt instanceof Composite || dt instanceof ghidra.program.model.data.Enum
            || dt instanceof TypeDef || dt instanceof FunctionDefinition;
    }

    private boolean isUserFacingDataType(DataType dt) {
        if (dt == null) return false;
        // CParser also exposes the function definitions backing typedefs. They
        // belong under functions even when reached through a contained type
        // rather than the parser's function map.
        return !(dt instanceof FunctionDefinition);
    }

    private DataType findBestParsedDataType(String name, Set<DataType> parsed,
            CategoryPath preferred) {
        DataType best = null;
        for (DataType dt : parsed) {
            if (!dt.getName().equals(name)) continue;
            if (dt.getCategoryPath().equals(preferred)) {
                return dt;
            }
            if (best == null) best = dt;
        }
        return best;
    }
}
