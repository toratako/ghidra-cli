package ghidracli;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import ghidra.app.util.cparser.C.CParser;
import ghidra.app.util.cparser.C.ParseException;
import ghidra.program.model.data.Category;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
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

        try {
            DataTypeManager dtm = session.program().getDataTypeManager();

            String processedCode = code.trim();
            if (!processedCode.endsWith(";")) {
                processedCode += ";";
            }

            ProgramTransaction transaction = session.transaction("Import C types");
            try {
                CParser parser = new CParser(dtm, true,
                    new DataTypeManager[] { dtm });
                parser.parse(processedCode);
                String parseMessages = parser.getParseMessages();

                Set<String> definedNames = new HashSet<>();
                definedNames.addAll(parser.getComposites().keySet());
                definedNames.addAll(parser.getEnums().keySet());
                definedNames.addAll(parser.getTypes().keySet());
                definedNames.addAll(parser.getFunctions().keySet());

                Set<DataType> parsedTypes = new HashSet<>();
                parsedTypes.addAll(parser.getComposites().values());
                parsedTypes.addAll(parser.getEnums().values());
                parsedTypes.addAll(parser.getTypes().values());
                parsedTypes.addAll(parser.getFunctions().values());

                CategoryPath lookupPath = CategoryPath.ROOT;
                if (categoryPath != null) {
                    String normalizedPath = categoryPath.startsWith("/")
                        ? categoryPath : "/" + categoryPath;
                    CategoryPath targetPath = new CategoryPath(normalizedPath);
                    Category targetCat = dtm.createCategory(targetPath);

                    for (DataType dt : parsedTypes) {
                        if (!isUserFacingDataType(dt)) continue;
                        if (dt.getCategoryPath().equals(targetPath)) continue;
                        targetCat.moveDataType(dt, DataTypeConflictHandler.REPLACE_HANDLER);
                    }
                    lookupPath = targetPath;
                }

                transaction.end(true);

                JsonArray typesArray = new JsonArray();
                for (String name : definedNames) {
                    DataType best = findBestParsedDataType(name, parsedTypes, lookupPath);
                    if (best == null) {
                        best = findBestDataType(dtm, name, lookupPath);
                    }
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
            } catch (Exception e) {
                transaction.end(false);
                throw e;
            }
        } catch (ParseException pe) {
            return errorResult("C parse error: " + pe.getMessage());
        } catch (Exception e) {
            return errorResult("Failed to import C types: " + e.getMessage());
        }
    }

    private List<DataType> findUserDataTypes(DataTypeManager dtm, String name) {
        List<DataType> all = new ArrayList<>();
        dtm.findDataTypes(name, all);
        List<DataType> result = new ArrayList<>();
        for (DataType dt : all) {
            if (!dt.getName().equals(name)) continue;
            if (!isUserFacingDataType(dt)) continue;
            result.add(dt);
        }
        return result;
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

    private DataType findBestDataType(DataTypeManager dtm, String name,
            CategoryPath preferred) {
        DataType best = null;
        for (DataType dt : findUserDataTypes(dtm, name)) {
            if (dt.getCategoryPath().equals(preferred)) {
                return dt;
            }
            if (best == null) best = dt;
        }
        return best;
    }
}
