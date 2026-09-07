package ghidracli;

import com.google.gson.JsonObject;
import static ghidracli.JsonProtocol.errorResponse;
import static ghidracli.JsonProtocol.errorResult;
import static ghidracli.JsonProtocol.successResponse;

final class CommandDispatcher {
    private final FunctionCommands functionCommands;
    private final ProgramCommands programCommands;
    private final ListingCommands listingCommands;
    private final XrefCommands xrefCommands;
    private final SearchCommands searchCommands;
    private final SymbolCommands symbolCommands;
    private final TypeCommands typeCommands;
    private final TagCommands tagCommands;
    private final PcodeCommands pcodeCommands;
    private final AnalysisCommands analysisCommands;
    private final CommentCommands commentCommands;
    private final GraphCommands graphCommands;
    private final DiffCommands diffCommands;
    private final MemoryCommands memoryCommands;
    private final ScriptCommands scriptCommands;
    private final DecompileCommands decompileCommands;
    private final FunctionSignatureCommands functionSignatureCommands;
    private final TypeImportCommands typeImportCommands;

    CommandDispatcher(ProgramSession session) {
        AddressResolver addressResolver = new AddressResolver(session);
        TypeResolver typeResolver = new TypeResolver(session);
        FunctionQueries functionQueries = new FunctionQueries(session, addressResolver);
        ArtifactManifest artifacts = new ArtifactManifest(session);
        functionCommands = new FunctionCommands(session, addressResolver, functionQueries);
        decompileCommands = new DecompileCommands(session, addressResolver, functionQueries);
        functionSignatureCommands = new FunctionSignatureCommands(session, functionQueries, typeResolver);
        typeImportCommands = new TypeImportCommands(session);
        programCommands = new ProgramCommands(session);
        listingCommands = new ListingCommands(session);
        xrefCommands = new XrefCommands(session, addressResolver, functionQueries);
        searchCommands = new SearchCommands(session, functionQueries);
        symbolCommands = new SymbolCommands(session);
        typeCommands = new TypeCommands(session, typeResolver);
        tagCommands = new TagCommands(session, functionQueries);
        pcodeCommands = new PcodeCommands(session, addressResolver, functionQueries);
        analysisCommands = new AnalysisCommands(session);
        commentCommands = new CommentCommands(session);
        graphCommands = new GraphCommands(session, functionQueries);
        diffCommands = new DiffCommands(session, functionQueries);
        memoryCommands = new MemoryCommands(session, addressResolver);
        scriptCommands = new ScriptCommands(session, artifacts);
    }

    private JsonObject dispatchCommand(String command, JsonObject args) {
        if (command == null) return null;
        switch (command) {
            case "program_info":    return programCommands.handleProgramInfo();
            case "list_functions":  return functionCommands.handleListFunctions(args);
            case "get_function":    return functionCommands.handleGetFunction(args);
            case "rename_function": return functionCommands.handleRenameFunction(args);
            case "create_function": return functionCommands.handleCreateFunction(args);
            case "delete_function": return functionCommands.handleDeleteFunction(args);
            case "decompile":       return decompileCommands.handleDecompile(args);
            case "list_strings":    return listingCommands.handleListStrings(args);
            case "list_imports":    return listingCommands.handleListImports(args);
            case "list_exports":    return listingCommands.handleListExports(args);
            case "memory_map":      return listingCommands.handleMemoryMap();
            case "xrefs_to":        return xrefCommands.handleXrefsTo(args);
            case "xrefs_from":      return xrefCommands.handleXrefsFrom(args);
            case "xrefs_list":      return xrefCommands.handleXrefsList(args);
            case "import":          return programCommands.handleImport(args);
            case "analyze":         return programCommands.handleAnalyze(args);
            case "list_programs":   return programCommands.handleListPrograms();
            case "open_program":    return programCommands.handleOpenProgram(args);
            case "program_close":   return programCommands.handleProgramClose();
            case "program_delete":  return programCommands.handleProgramDelete(args);
            case "program_export":  return programCommands.handleProgramExport(args);
            // Find commands
            case "find_string":     return searchCommands.handleFindString(args);
            case "string_refs":     return searchCommands.handleStringRefs(args);
            case "find_bytes":      return searchCommands.handleFindBytes(args);
            case "find_function":   return searchCommands.handleFindFunction(args);
            case "find_calls":      return searchCommands.handleFindCalls(args);
            case "find_crypto":     return searchCommands.handleFindCrypto();
            case "find_interesting": return searchCommands.handleFindInteresting();
            // Symbol commands
            case "symbol_list":     return symbolCommands.handleSymbolList(args);
            case "symbol_get":      return symbolCommands.handleSymbolGet(args);
            case "symbol_create":   return symbolCommands.handleSymbolCreate(args);
            case "symbol_delete":   return symbolCommands.handleSymbolDelete(args);
            case "symbol_rename":   return symbolCommands.handleSymbolRename(args);
            // Type commands
            case "type_list":       return typeCommands.handleTypeList(args);
            case "type_get":        return typeCommands.handleTypeGet(args);
            case "type_create":     return typeCommands.handleTypeCreate(args);
            case "type_apply":      return typeCommands.handleTypeApply(args);
            case "type_import_c":   return typeImportCommands.handleTypeImportC(args);
            case "type_delete":     return typeCommands.handleTypeDelete(args);
            case "type_rename":     return typeCommands.handleTypeRename(args);
            case "type_create_enum": return typeCommands.handleTypeCreateEnum(args);
            case "type_typedef":    return typeCommands.handleTypeTypedef(args);
            case "type_add_field":  return typeCommands.handleTypeAddField(args);
            case "type_del_field":  return typeCommands.handleTypeDelField(args);
            // Tag commands
            case "tag_list":        return tagCommands.handleTagList(args);
            case "tag_get":         return tagCommands.handleTagGet(args);
            case "tag_create":      return tagCommands.handleTagCreate(args);
            case "tag_delete":      return tagCommands.handleTagDelete(args);
            case "tag_rename":      return tagCommands.handleTagRename(args);
            case "tag_set_comment": return tagCommands.handleTagSetComment(args);
            case "tag_add":         return tagCommands.handleTagAdd(args);
            case "tag_remove":      return tagCommands.handleTagRemove(args);
            // Function signature commands
            case "function_set_signature": return functionSignatureCommands.handleFunctionSetSignature(args);
            case "function_set_return_type": return functionSignatureCommands.handleFunctionSetReturnType(args);
            case "function_set_calling_convention": return functionSignatureCommands.handleFunctionSetCallingConvention(args);
            case "function_set_noreturn": return functionSignatureCommands.handleFunctionSetNoReturn(args);
            case "function_tag_add":    return tagCommands.handleFunctionTagAdd(args);
            case "function_tag_remove": return tagCommands.handleFunctionTagRemove(args);
            case "function_tag_list":   return tagCommands.handleFunctionTagList(args);
            case "set_var_type":    return functionSignatureCommands.handleSetVarType(args);
            // PCode commands
            case "pcode_at":        return pcodeCommands.handlePcodeAt(args);
            case "pcode_function":  return pcodeCommands.handlePcodeFunction(args);
            // Analysis control
            case "analyzer_list":   return analysisCommands.handleAnalyzerList(args);
            case "analyzer_set":    return analysisCommands.handleAnalyzerSet(args);
            case "analyze_run":     return analysisCommands.handleAnalyzeRun(args);
            // Comment commands
            case "comment_list":    return commentCommands.handleCommentList(args);
            case "comment_get":     return commentCommands.handleCommentGet(args);
            case "comment_set":     return commentCommands.handleCommentSet(args);
            case "comment_delete":  return commentCommands.handleCommentDelete(args);
            // Graph commands
            case "graph_calls":     return graphCommands.handleGraphCalls(args);
            case "graph_callers":   return graphCommands.handleGraphCallers(args);
            case "graph_callees":   return graphCommands.handleGraphCallees(args);
            case "graph_export":    return graphCommands.handleGraphExport(args);
            // Diff commands
            case "diff_programs":   return diffCommands.handleDiffPrograms(args);
            case "diff_functions":  return diffCommands.handleDiffFunctions(args);
            // Patch commands
            case "patch_bytes":     return memoryCommands.handlePatchBytes(args);
            case "patch_nop":       return memoryCommands.handlePatchNop(args);
            case "patch_export":    return memoryCommands.handlePatchExport(args);
            // Other commands
            case "disasm":          return memoryCommands.handleDisasm(args);
            case "disasm_at":       return memoryCommands.handleDisasmAt(args);
            case "clear_range":     return memoryCommands.handleClearRange(args);
            case "stats":           return programCommands.handleStats();
            // Script commands
            case "script_run":      return scriptCommands.handleScriptRun(args);
            case "script_java":     return scriptCommands.handleScriptJava(args);
            case "script_python":   return scriptCommands.handleScriptPython(args);
            case "script_list":     return scriptCommands.handleScriptList();
            // Batch
            case "batch":           return errorResult("Batch operations are handled by the CLI, not via bridge script");
            // Memory read
            case "read_memory":     return memoryCommands.handleReadMemory(args);
            default:                return null;
        }
    }
    JsonObject execute(String command, JsonObject args) {
        try {
            JsonObject result = dispatchCommand(command, args);
            if (result == null) {
    /**
     * Error response carrying structured detail (e.g. a conflicting code
     * unit's type/range, or a containing function's name/entry/size) alongside
     * the message, so callers can act on it without a follow-up round trip.
     */
                return errorResponse("Unknown command: " + command);
            }

            if (result.has("error")) {
                JsonObject detail = (result.has("detail") && result.get("detail").isJsonObject())
                    ? result.getAsJsonObject("detail") : null;
                return errorResponse(result.get("error").getAsString(), detail);
            }

            return successResponse(result);
        } catch (Exception e) {
            return errorResponse(e.getMessage());
        }
    }
}
