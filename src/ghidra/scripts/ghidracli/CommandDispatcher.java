package ghidracli;

import com.google.gson.JsonObject;
import static ghidracli.JsonProtocol.errorResponse;
import static ghidracli.JsonProtocol.errorResult;
import static ghidracli.JsonProtocol.successResponse;

final class CommandDispatcher {
    private final ProgramSession session;
    private final FunctionCommands functionCommands;
    private final ProgramCommands programCommands;
    private final ProgramContextCommands programContextCommands;
    private final ProgramRebaseCommands programRebaseCommands;
    private final ProgramExportCommands programExportCommands;
    private final ListingCommands listingCommands;
    private final XrefCommands xrefCommands;
    private final SearchCommands searchCommands;
    private final SymbolCommands symbolCommands;
    private final TypeCommands typeCommands;
    private final TagCommands tagCommands;
    private final PcodeCommands pcodeCommands;
    private final AnalysisCommands analysisCommands;
    private final CommentCommands commentCommands;
    private final BookmarkCommands bookmarkCommands;
    private final GraphCommands graphCommands;
    private final MemoryCommands memoryCommands;
    private final MemoryInfoCommands memoryInfoCommands;
    private final DataCommands dataCommands;
    private final ScriptCommands scriptCommands;
    private final DecompileCommands decompileCommands;
    private final FunctionSignatureCommands functionSignatureCommands;
    private final TypeImportCommands typeImportCommands;

    CommandDispatcher(ProgramSession session) {
        this.session = session;
        AddressResolver addressResolver = new AddressResolver(session);
        TypeResolver typeResolver = new TypeResolver(session);
        FunctionQueries functionQueries = new FunctionQueries(session, addressResolver);
        StringQueries stringQueries = new StringQueries(session);
        ArtifactManifest artifacts = new ArtifactManifest(session);
        functionCommands = new FunctionCommands(session, addressResolver, functionQueries);
        decompileCommands = new DecompileCommands(session, functionQueries);
        functionSignatureCommands = new FunctionSignatureCommands(session, functionQueries, typeResolver);
        typeImportCommands = new TypeImportCommands(session);
        programCommands = new ProgramCommands(session);
        programContextCommands = new ProgramContextCommands(session);
        programRebaseCommands = new ProgramRebaseCommands(session);
        programExportCommands = new ProgramExportCommands(session);
        listingCommands = new ListingCommands(session, stringQueries);
        xrefCommands = new XrefCommands(session, addressResolver, functionQueries);
        searchCommands = new SearchCommands(session, addressResolver, stringQueries);
        symbolCommands = new SymbolCommands(session);
        typeCommands = new TypeCommands(session, typeResolver);
        tagCommands = new TagCommands(session, functionQueries);
        pcodeCommands = new PcodeCommands(session, addressResolver, functionQueries);
        analysisCommands = new AnalysisCommands(session);
        commentCommands = new CommentCommands(session);
        bookmarkCommands = new BookmarkCommands(session);
        graphCommands = new GraphCommands(session, functionQueries);
        memoryCommands = new MemoryCommands(session, addressResolver, functionQueries);
        memoryInfoCommands = new MemoryInfoCommands(session, addressResolver);
        dataCommands = new DataCommands(session, addressResolver);
        scriptCommands = new ScriptCommands(session, artifacts);
    }

    private JsonObject dispatchCommand(String command, JsonObject args) throws Exception {
        if (command == null) return null;
        switch (command) {
            case "program_info":    return programCommands.handleProgramInfo();
            case "program_context_list": return programContextCommands.handleList(args);
            case "program_context_get": return programContextCommands.handleGet(args);
            case "program_context_set": return programContextCommands.handleSet(args);
            case "program_context_clear": return programContextCommands.handleClear(args);
            case "program_rebase": return programRebaseCommands.handleRebase(args);
            case "program_list_relocations": return programCommands.handleListRelocations();
            case "list_functions":  return functionCommands.handleListFunctions(args);
            case "get_function":    return functionCommands.handleGetFunction(args);
            case "function_list_calling_conventions": return functionCommands.handleListCallingConventions();
            case "function_disasm": return memoryCommands.handleFunctionDisasm(args);
            case "rename_function": return functionCommands.handleRenameFunction(args);
            case "create_function": return functionCommands.handleCreateFunction(args);
            case "delete_function": return functionCommands.handleDeleteFunction(args);
            case "decompile":       return decompileCommands.handleDecompile(args);
            case "list_strings":    return listingCommands.handleListStrings(args);
            case "symbol_externals":    return listingCommands.handleSymbolExternals(args);
            case "symbol_entry_points":    return listingCommands.handleSymbolEntryPoints(args);
            case "memory_map":      return listingCommands.handleMemoryMap();
            case "memory_info":     return memoryInfoCommands.handleInfo(args);
            case "data_list":       return dataCommands.handleList(args);
            case "data_read":       return dataCommands.handleRead(args);
            case "xrefs_to":        return xrefCommands.handleXrefsTo(args);
            case "xrefs_from":      return xrefCommands.handleXrefsFrom(args);
            case "import":          return programCommands.handleImport(args);
            case "analysis_run":    return analysisCommands.handleRun(args);
            case "list_programs":   return programCommands.handleListPrograms();
            case "open_program":    return programCommands.handleOpenProgram(args);
            case "program_close":   return programCommands.handleProgramClose();
            case "program_save":    return programCommands.handleProgramSave();
            case "program_delete":  return programCommands.handleProgramDelete(args);
            case "program_export":  return programExportCommands.handleProgramExport(args);
            // Find commands
            case "find_string":     return searchCommands.handleFindString(args);
            case "find_text":       return searchCommands.handleFindText(args);
            case "string_refs":     return searchCommands.handleStringRefs(args);
            case "find_bytes":      return searchCommands.handleFindBytes(args);
            case "find_bytes_regex": return searchCommands.handleFindBytesRegex(args);
            case "find_instruction": return searchCommands.handleFindInstruction(args);
            case "find_constant": return searchCommands.handleFindConstant(args);
            // Symbol commands
            case "symbol_list":     return symbolCommands.handleSymbolList(args);
            case "symbol_get":      return symbolCommands.handleSymbolGet(args);
            case "symbol_get_by_name": return symbolCommands.handleSymbolGetByName(args);
            case "symbol_create_label":   return symbolCommands.handleSymbolCreateLabel(args);
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
            case "type_create_union": return typeCommands.handleTypeCreateUnion(args);
            case "type_enum_member_delete": return typeCommands.handleTypeEnumMemberDelete(args);
            case "type_typedef":    return typeCommands.handleTypeTypedef(args);
            case "type_field_append":  return typeCommands.handleTypeFieldAppend(args);
            case "type_field_set":  return typeCommands.handleTypeFieldSet(args);
            case "type_field_clear": return typeCommands.handleTypeFieldClear(args);
            case "type_field_delete":  return typeCommands.handleTypeFieldDelete(args);
            // Tag commands
            case "tag_list":        return tagCommands.handleTagList(args);
            case "tag_get":         return tagCommands.handleTagGet(args);
            case "tag_create":      return tagCommands.handleTagCreate(args);
            case "tag_delete":      return tagCommands.handleTagDelete(args);
            case "tag_rename":      return tagCommands.handleTagRename(args);
            case "tag_set_comment": return tagCommands.handleTagSetComment(args);
            case "tag_attach":      return tagCommands.handleTagAttach(args);
            case "tag_detach":      return tagCommands.handleTagDetach(args);
            // Function signature commands
            case "function_set_signature": return functionSignatureCommands.handleFunctionSetSignature(args);
            case "function_set_return_type": return functionSignatureCommands.handleFunctionSetReturnType(args);
            case "function_set_calling_convention": return functionSignatureCommands.handleFunctionSetCallingConvention(args);
            case "function_set_stack_purge": return functionSignatureCommands.handleFunctionSetStackPurge(args);
            case "function_set_noreturn": return functionSignatureCommands.handleFunctionSetNoReturn(args);
            case "function_edit_var": return functionSignatureCommands.handleFunctionEditVar(args);
            // PCode commands
            case "pcode_at":        return pcodeCommands.handlePcodeAt(args);
            case "pcode_function":  return pcodeCommands.handlePcodeFunction(args);
            // Analysis control
            case "analysis_option_list": return analysisCommands.handleOptionList(args);
            case "analysis_option_get":  return analysisCommands.handleOptionGet(args);
            case "analysis_option_set":  return analysisCommands.handleOptionSet(args);
            // Comment commands
            case "comment_list":    return commentCommands.handleCommentList(args);
            case "comment_get":     return commentCommands.handleCommentGet(args);
            case "comment_set":     return commentCommands.handleCommentSet(args);
            case "comment_delete":  return commentCommands.handleCommentDelete(args);
            // Bookmark queries
            case "bookmark_list":   return bookmarkCommands.handleList();
            case "bookmark_get":    return bookmarkCommands.handleGet(args);
            // Graph commands
            case "graph_calls":     return graphCommands.handleGraphCalls(args);
            case "graph_callers":   return graphCommands.handleGraphCallers(args);
            case "graph_callees":   return graphCommands.handleGraphCallees(args);
            // Memory writes
            case "memory_write":    return memoryCommands.handleMemoryWrite(args);
            // Other commands
            case "disasm":          return memoryCommands.handleDisasm(args);
            case "disasm_range":    return memoryCommands.handleDisasmRange(args);
            case "define_code":     return memoryCommands.handleDefineCode(args);
            case "clear_range":     return memoryCommands.handleClearRange(args);
            case "stats":           return programCommands.handleStats();
            // Script commands
            case "script_run":      return scriptCommands.handleScriptRun(args);
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
            session.beginRequest(command);
        } catch (Exception e) {
            return errorResponse(e.getMessage(), JsonProtocol.errorDetail(e));
        }
        JsonObject response = executeCommand(command, args);
        try {
            boolean successful = "success".equals(response.get("status").getAsString());
            ProgramSession.RequestOutcome outcome = session.finishRequest(successful);
            if (outcome.rolledBack() && successful) {
                response = errorResponse(outcome.cancelled() ? "Command cancelled"
                    : "Ghidra aborted the command transaction");
            }
            if ("error".equals(response.get("status").getAsString())) {
                JsonObject detail = response.has("detail")
                    ? response.getAsJsonObject("detail") : new JsonObject();
                if ("analysis_run".equals(command)) detail.addProperty("saved", outcome.saved());
                if (outcome.rolledBack()) detail.addProperty("rolled_back", true);
                else if (outcome.saved()) detail.addProperty("partial_changes_saved", true);
                if (outcome.cancelled()) detail.addProperty("cancelled", true);
                // Capture identity on the program lane. A later bridge_info
                // query could observe another client's program selection.
                if (outcome.rolledBack() && session.program() != null)
                    detail.addProperty("program", session.programPath());
                if (detail.size() != 0) response.add("detail", detail);
            } else if ("analysis_run".equals(command)) {
                // The save boundary completed, including when no write was necessary.
                response.getAsJsonObject("data").addProperty("saved", true);
            }
            return response;
        } catch (ProgramSession.SaveFailure e) {
            JsonObject detail = new JsonObject();
            detail.addProperty("saved", false);
            detail.addProperty("save_failed", true);
            detail.addProperty("command", command);
            if (session.program() != null) {
                detail.addProperty("program", session.program().getDomainFile().getPathname());
            }
            detail.add("command_response", response);
            return errorResponse("Auto-save failed: " + e.getMessage()
                + ". Changes may remain in memory. Retry `ghidra-cli program save` for this project/program; "
                + "do not repeat the editing command or stop the bridge before saving.", detail);
        } catch (Exception e) {
            JsonObject detail = JsonProtocol.errorDetail(e);
            if (detail == null) detail = new JsonObject();
            detail.addProperty("transaction_failed", true);
            detail.add("command_response", response);
            return errorResponse("Could not finish command transaction: " + e.getMessage(), detail);
        }
    }

    private JsonObject executeCommand(String command, JsonObject args) {
        try {
            JsonObject result = dispatchCommand(command, args);
            if (result == null) {
                return errorResponse("Unknown command: " + command);
            }

            if (result.has("error")) {
                JsonObject detail = (result.has("detail") && result.get("detail").isJsonObject())
                    ? result.getAsJsonObject("detail").deepCopy() : new JsonObject();
                // Handlers may attach diagnostics beside the error message.
                // Carry them into the wire detail without replacing structured conflicts.
                for (java.util.Map.Entry<String, com.google.gson.JsonElement> field : result.entrySet()) {
                    if (!field.getKey().equals("error") && !field.getKey().equals("detail")
                            && !detail.has(field.getKey())) {
                        detail.add(field.getKey(), field.getValue());
                    }
                }
                return errorResponse(result.get("error").getAsString(), detail.size() == 0 ? null : detail);
            }

            return successResponse(result);
        } catch (Exception e) {
            return errorResponse(e.getMessage(), JsonProtocol.errorDetail(e));
        }
    }
}
