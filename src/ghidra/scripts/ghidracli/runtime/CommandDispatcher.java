package ghidracli.runtime;

import com.google.gson.JsonObject;
import ghidracli.analysis.AnalysisCommands;
import ghidracli.analysis.DecompileCommands;
import ghidracli.analysis.GraphCommands;
import ghidracli.analysis.InstructionCfg;
import ghidracli.analysis.PcodeCommands;
import ghidracli.analysis.StructureInferenceCommands;
import ghidracli.analysis.VtableCommands;
import ghidracli.function.FunctionBodyCommands;
import ghidracli.function.FunctionCallSignatureCommands;
import ghidracli.function.FunctionCommands;
import ghidracli.function.FunctionQueries;
import ghidracli.function.FunctionSignatureCommands;
import ghidracli.function.FunctionVariableCommands;
import ghidracli.function.TagCommands;
import ghidracli.listing.DataCommands;
import ghidracli.listing.AddressTableSearch;
import ghidracli.listing.InstructionListing;
import ghidracli.listing.ListingCommands;
import ghidracli.listing.ListingFlowCommands;
import ghidracli.listing.SearchCommands;
import ghidracli.listing.StringQueries;
import ghidracli.memory.FileMappingCommands;
import ghidracli.memory.MemoryBlockCommands;
import ghidracli.memory.MemoryCommands;
import ghidracli.memory.MemoryInfoCommands;
import ghidracli.program.ProgramCommands;
import ghidracli.program.ProgramContextCommands;
import ghidracli.program.ProgramExportCommands;
import ghidracli.program.ProgramRebaseCommands;
import ghidracli.protocol.JsonProtocol;
import ghidracli.query.AddressResolver;
import ghidracli.script.ScriptCommands;
import ghidracli.session.ProgramSession;
import ghidracli.symbol.BookmarkCommands;
import ghidracli.symbol.CommentCommands;
import ghidracli.symbol.EquateCommands;
import ghidracli.symbol.NamespaceCommands;
import ghidracli.symbol.SymbolCommands;
import ghidracli.symbol.XrefCommands;
import ghidracli.types.BitFieldCommands;
import ghidracli.types.TypeCommands;
import ghidracli.types.TypeDefinitionCommands;
import ghidracli.types.TypeImportCommands;
import ghidracli.types.TypeResizeCommands;
import ghidracli.types.TypeResolver;
import ghidracli.types.TypeUsesCommands;

import static ghidracli.protocol.JsonProtocol.errorResponse;
import static ghidracli.protocol.JsonProtocol.errorResult;
import static ghidracli.protocol.JsonProtocol.successResponse;

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
    private final AddressTableSearch addressTableSearch;
    private final VtableCommands vtableCommands;
    private final SymbolCommands symbolCommands;
    private final NamespaceCommands namespaceCommands;
    private final EquateCommands equateCommands;
    private final TypeCommands typeCommands;
    private final TypeUsesCommands typeUsesCommands;
    private final TypeDefinitionCommands typeDefinitionCommands;
    private final TypeResizeCommands typeResizeCommands;
    private final BitFieldCommands bitFieldCommands;
    private final TagCommands tagCommands;
    private final PcodeCommands pcodeCommands;
    private final AnalysisCommands analysisCommands;
    private final CommentCommands commentCommands;
    private final BookmarkCommands bookmarkCommands;
    private final GraphCommands graphCommands;
    private final InstructionCfg instructionCfg;
    private final MemoryCommands memoryCommands;
    private final MemoryInfoCommands memoryInfoCommands;
    private final FileMappingCommands fileMappingCommands;
    private final MemoryBlockCommands memoryBlockCommands;
    private final DataCommands dataCommands;
    private final ScriptCommands scriptCommands;
    private final DecompileCommands decompileCommands;
    private final FunctionSignatureCommands functionSignatureCommands;
    private final FunctionCallSignatureCommands functionCallSignatureCommands;
    private final FunctionBodyCommands functionBodyCommands;
    private final FunctionVariableCommands functionVariableCommands;
    private final StructureInferenceCommands structureInferenceCommands;
    private final ListingFlowCommands listingFlowCommands;
    private final TypeImportCommands typeImportCommands;

    CommandDispatcher(ProgramSession session) {
        this.session = session;
        AddressResolver addressResolver = new AddressResolver(session);
        TypeResolver typeResolver = new TypeResolver(session);
        FunctionQueries functionQueries = new FunctionQueries(session, addressResolver);
        StringQueries stringQueries = new StringQueries(session);
        InstructionListing instructions = new InstructionListing(session);
        functionCommands = new FunctionCommands(session, addressResolver, functionQueries, instructions);
        decompileCommands = new DecompileCommands(session, functionQueries);
        functionSignatureCommands = new FunctionSignatureCommands(session, functionQueries, typeResolver);
        functionCallSignatureCommands = new FunctionCallSignatureCommands(session, functionQueries);
        functionBodyCommands = new FunctionBodyCommands(session, functionQueries);
        functionVariableCommands = new FunctionVariableCommands(session, functionQueries, typeResolver);
        structureInferenceCommands = new StructureInferenceCommands(session, functionQueries);
        listingFlowCommands = new ListingFlowCommands(session);
        typeImportCommands = new TypeImportCommands(session);
        programCommands = new ProgramCommands(session);
        programContextCommands = new ProgramContextCommands(session);
        programRebaseCommands = new ProgramRebaseCommands(session);
        programExportCommands = new ProgramExportCommands(session);
        listingCommands = new ListingCommands(session, addressResolver, stringQueries, instructions);
        xrefCommands = new XrefCommands(session, addressResolver, functionQueries);
        searchCommands = new SearchCommands(session, addressResolver, stringQueries);
        addressTableSearch = new AddressTableSearch(session, addressResolver);
        vtableCommands = new VtableCommands(session, addressResolver);
        symbolCommands = new SymbolCommands(session);
        namespaceCommands = new NamespaceCommands(session);
        equateCommands = new EquateCommands(session);
        typeCommands = new TypeCommands(session, typeResolver);
        typeUsesCommands = new TypeUsesCommands(session, typeResolver);
        typeDefinitionCommands = new TypeDefinitionCommands(session, typeResolver);
        typeResizeCommands = new TypeResizeCommands(session, typeResolver);
        bitFieldCommands = new BitFieldCommands(session, typeResolver);
        tagCommands = new TagCommands(session, functionQueries);
        pcodeCommands = new PcodeCommands(session, addressResolver, functionQueries);
        analysisCommands = new AnalysisCommands(session);
        commentCommands = new CommentCommands(session);
        bookmarkCommands = new BookmarkCommands(session);
        graphCommands = new GraphCommands(session, functionQueries);
        instructionCfg = new InstructionCfg(session, functionQueries);
        memoryCommands = new MemoryCommands(session, addressResolver);
        memoryInfoCommands = new MemoryInfoCommands(session, addressResolver);
        fileMappingCommands = new FileMappingCommands(session);
        memoryBlockCommands = new MemoryBlockCommands(session);
        dataCommands = new DataCommands(session, addressResolver);
        scriptCommands = new ScriptCommands(session);
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
            case "function_disasm": return functionCommands.handleFunctionDisasm(args);
            case "rename_function": return functionCommands.handleRenameFunction(args);
            case "create_function": return functionCommands.handleCreateFunction(args);
            case "delete_function": return functionCommands.handleDeleteFunction(args);
            case "decompile":       return decompileCommands.handleDecompile(args);
            case "list_strings":    return listingCommands.handleListStrings(args);
            case "symbol_externals":    return symbolCommands.handleSymbolExternals(args);
            case "symbol_entry_points":    return symbolCommands.handleSymbolEntryPoints(args);
            case "memory_map":      return memoryInfoCommands.handleMemoryMap();
            case "memory_info":     return memoryInfoCommands.handleInfo(args);
            case "memory_file_mappings": return fileMappingCommands.handleFileMappings(args);
            case "memory_block_create": return memoryBlockCommands.handleCreate(args);
            case "memory_block_rename": return memoryBlockCommands.handleRename(args);
            case "memory_block_set_permissions": return memoryBlockCommands.handleSetPermissions(args);
            case "memory_block_set_volatile": return memoryBlockCommands.handleSetVolatile(args);
            case "memory_block_move": return memoryBlockCommands.handleMove(args);
            case "memory_block_delete": return memoryBlockCommands.handleDelete(args);
            case "data_list":       return dataCommands.handleList(args);
            case "data_read":       return dataCommands.handleRead(args);
            case "xrefs_to":        return xrefCommands.handleXrefsTo(args);
            case "xrefs_from":      return xrefCommands.handleXrefsFrom(args);
            case "xref_create_memory": return xrefCommands.handleCreateMemory(args);
            case "xref_delete": return xrefCommands.handleDelete(args);
            case "xref_set_primary": return xrefCommands.handleSetPrimary(args);
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
            case "symbol_set_namespace": return symbolCommands.handleSetNamespace(args);
            case "symbol_set_primary": return symbolCommands.handleSetPrimary(args);
            case "namespace_list": return namespaceCommands.handleList(args);
            case "namespace_get": return namespaceCommands.handleGet(args);
            case "namespace_create": return namespaceCommands.handleCreate(args);
            // Equate definitions and operand associations
            case "equate_list": return equateCommands.handleList(args);
            case "equate_get": return equateCommands.handleGet(args);
            case "equate_create": return equateCommands.handleCreate(args);
            case "equate_attach": return equateCommands.handleAttach(args);
            case "equate_detach": return equateCommands.handleDetach(args);
            case "equate_delete": return equateCommands.handleDelete(args);
            // Type commands
            case "type_list":       return typeCommands.handleTypeList(args);
            case "type_get":        return typeCommands.handleTypeGet(args);
            case "type_uses":       return typeUsesCommands.handleUses(args);
            case "type_clone":      return typeDefinitionCommands.handleClone(args);
            case "type_move":       return typeDefinitionCommands.handleMove(args);
            case "type_resize":     return typeResizeCommands.handleResize(args);
            case "type_category_list": return typeDefinitionCommands.handleCategoryList(args);
            case "type_category_create": return typeDefinitionCommands.handleCategoryCreate(args);
            case "type_category_delete": return typeDefinitionCommands.handleCategoryDelete(args);
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
            case "type_field_create_bitfield": return bitFieldCommands.handleCreate(args);
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
            case "function_set_body": return functionBodyCommands.handleSet(args);
            case "function_call_signature_get": return functionCallSignatureCommands.handleGet(args);
            case "function_call_signature_set": return functionCallSignatureCommands.handleSet(args);
            case "function_call_signature_clear": return functionCallSignatureCommands.handleClear(args);
            case "function_var_list": return functionVariableCommands.handleFunctionVarList(args);
            case "function_var_get": return functionVariableCommands.handleFunctionVarGet(args);
            case "function_var_set": return functionVariableCommands.handleFunctionVarSet(args);
            case "function_var_infer_struct": return structureInferenceCommands.handleInfer(args);
            case "listing_flow_get": return listingFlowCommands.handleGet(args);
            case "listing_flow_set": return listingFlowCommands.handleSet(args);
            case "listing_flow_clear": return listingFlowCommands.handleClear(args);
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
            // Bookmarks
            case "bookmark_list":   return bookmarkCommands.handleList();
            case "bookmark_get":    return bookmarkCommands.handleGet(args);
            case "bookmark_set": return bookmarkCommands.handleSet(args);
            case "bookmark_delete": return bookmarkCommands.handleDelete(args);
            // Graph commands
            case "graph_calls":     return graphCommands.handleGraphCalls(args);
            case "graph_cfg":       return instructionCfg.handle(args);
            case "graph_callers":   return graphCommands.handleGraphCallers(args);
            case "graph_callees":   return graphCommands.handleGraphCallees(args);
            // Memory writes
            case "memory_write":    return memoryCommands.handleMemoryWrite(args);
            // Other commands
            case "disasm":          return listingCommands.handleDisasm(args);
            case "disasm_range":    return listingCommands.handleDisasmRange(args);
            case "define_code":     return listingCommands.handleDefineCode(args);
            case "clear_range":     return listingCommands.handleClearRange(args);
            case "stats":           return programCommands.handleStats();
            // Script commands
            case "script_run":      return scriptCommands.handleScriptRun(args);
            case "script_list":     return scriptCommands.handleScriptList();
            // Batch
            case "batch":           return errorResult("Batch operations are handled by the CLI, not via bridge script");
            // Memory read
            case "read_memory":     return memoryCommands.handleReadMemory(args);
            case "vtable_read":     return vtableCommands.handleRead(args);
            case "find_address_tables": return addressTableSearch.handleFindAddressTables(args);
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
