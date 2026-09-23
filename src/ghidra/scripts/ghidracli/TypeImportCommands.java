package ghidracli;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import ghidra.app.util.cparser.C.CParser;
import ghidra.app.util.cparser.C.ParseException;
import ghidra.app.util.cparser.C.TokenMgrError;
import ghidra.program.database.data.DataTypeUtilities;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.StandAloneDataTypeManager;
import ghidra.program.model.data.TypeDef;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.Map;
import java.util.Set;
import static ghidracli.JsonProtocol.errorResult;
import static ghidracli.JsonProtocol.getArgString;

final class TypeImportCommands {
    private final ProgramSession session;

    TypeImportCommands(ProgramSession session) {
        this.session = session;
    }

    JsonObject handleTypeImportC(JsonObject args) {
        if (session.program() == null) return errorResult("No program loaded");

        String code = getArgString(args, "code");
        if (code == null || code.trim().isEmpty()) {
            return errorResult("C code required");
        }

        String categoryPath = getArgString(args, "category");

        DataTypeManager dtm = session.program().getDataTypeManager();
        try (StandAloneDataTypeManager parsedManager = new StandAloneDataTypeManager(
                "C import", dtm.getDataOrganization())) {

            String processedCode = code.trim();
            if (!processedCode.endsWith(";")) {
                processedCode += ";";
            }

            // Parse without changing the Program, retaining existing references'
            // source identities until the definitions are staged and relocated.
            CParser parser = new CParser(parsedManager, false,
                new DataTypeManager[] { dtm });
            parser.setMonitor(session.monitor());
            parser.parse(processedCode);
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
            return errorResult("Failed to import C types: " + e.getMessage());
        }
    }

    private boolean isDefinition(DataType dt) {
        return dt instanceof Composite || dt instanceof ghidra.program.model.data.Enum
            || dt instanceof TypeDef || dt instanceof FunctionDefinition;
    }

    private boolean isUserFacingDataType(DataType dt) {
        if (dt == null) return false;
        return !dt.getCategoryPath().toString().equals("/functions");
    }

    private DataType findBestParsedDataType(String name, Set<DataType> parsed,
            CategoryPath preferred) {
        DataType best = null;
        for (DataType dt : parsed) {
            if (!isUserFacingDataType(dt)) continue;
            if (!dt.getName().equals(name)) continue;
            if (dt.getCategoryPath().equals(preferred)) {
                return dt;
            }
            if (best == null) best = dt;
        }
        return best;
    }
}
