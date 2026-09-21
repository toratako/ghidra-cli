package ghidracli;

import com.google.gson.JsonArray;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Set;
import static ghidracli.JsonProtocol.errorResult;
import static ghidracli.JsonProtocol.getArgString;
import static ghidracli.JsonProtocol.getArgBool;

final class XrefCommands {
    private final ProgramSession session;
    private final AddressResolver addressResolver;
    private final FunctionQueries functionQueries;

    XrefCommands(ProgramSession session, AddressResolver addressResolver, FunctionQueries functionQueries) {
        this.session = session;
        this.addressResolver = addressResolver;
        this.functionQueries = functionQueries;
    }

    JsonObject handleXrefsTo(JsonObject args) throws ghidra.util.exception.CancelledException {
        if (session.program() == null) {
            return errorResult("No program loaded");
        }

        String addrStr = getArgString(args, "address");
        if (addrStr == null || addrStr.isEmpty()) {
            return errorResult("No address provided");
        }

        LinkedHashSet<Address> targetAddrs = addressResolver.resolveXrefTargets(addrStr);
        if (targetAddrs.isEmpty()) {
            return errorResult(functionQueries.buildFunctionTargetHint(addrStr));
        }

        JsonArray xrefs = new JsonArray();
        ReferenceManager refMgr = session.program().getReferenceManager();
        FunctionManager fm = session.program().getFunctionManager();
        SymbolTable st = session.program().getSymbolTable();
        Set<String> seen = new HashSet<>();

        for (Address addr : targetAddrs) {
            session.monitor().checkCancelled();
            for (Reference ref : refMgr.getReferencesTo(addr)) {
                session.monitor().checkCancelled();
                Address fromAddr = ref.getFromAddress();
                String dedupKey = AddressCodec.format(fromAddr) + "|" + AddressCodec.format(addr)
                    + "|" + ref.getOperandIndex() + "|" + ref.getReferenceType();
                if (!seen.add(dedupKey)) continue;

                Function fromFunc = fm.getFunctionContaining(fromAddr);
                Function toFunc = fm.getFunctionContaining(addr);

                JsonObject xrefData = new JsonObject();
                xrefData.addProperty("from", AddressCodec.format(fromAddr));
                xrefData.addProperty("to", AddressCodec.format(addr));
                xrefData.addProperty("ref_type", ref.getReferenceType().toString());
                addReferenceMetadata(xrefData, ref);
                if (fromFunc != null) {
                    xrefData.addProperty("from_function", fromFunc.getName());
                } else {
                    xrefData.add("from_function", JsonNull.INSTANCE);
                }
                if (toFunc != null) {
                    xrefData.addProperty("to_function", toFunc.getName());
                } else {
                    Symbol toSym = st.getPrimarySymbol(addr);
                    if (toSym != null) {
                        xrefData.addProperty("to_function", toSym.getName());
                    } else {
                        xrefData.add("to_function", JsonNull.INSTANCE);
                    }
                }
                xrefs.add(xrefData);
            }
        }

        JsonObject result = new JsonObject();
        result.add("xrefs", xrefs);
        result.addProperty("count", xrefs.size());
        return result;
    }

    JsonObject handleXrefsFrom(JsonObject args) throws ghidra.util.exception.CancelledException {
        if (session.program() == null) return errorResult("No program loaded");

        String target = getArgString(args, "address");
        if (target == null || target.isEmpty()) return errorResult("No address provided");

        JsonArray xrefs = new JsonArray();
        if (getArgBool(args, "function", false)) {
            Function function = functionQueries.findFunctionByNameOrAddress(target);
            if (function == null) return errorResult(functionQueries.buildFunctionTargetHint(target));
            ghidra.program.model.address.AddressIterator addresses = function.getBody().getAddresses(true);
            while (addresses.hasNext()) {
                session.monitor().checkCancelled();
                appendReferencesFrom(addresses.next(), xrefs);
            }
        } else {
            Address address = addressResolver.resolveAddress(target);
            if (address == null) return errorResult(functionQueries.buildFunctionTargetHint(target));
            appendReferencesFrom(address, xrefs);
        }

        JsonObject result = new JsonObject();
        result.add("xrefs", xrefs);
        result.addProperty("count", xrefs.size());
        return result;
    }

    private void appendReferencesFrom(Address address, JsonArray xrefs)
            throws ghidra.util.exception.CancelledException {
        FunctionManager functions = session.program().getFunctionManager();
        Function fromFunction = functions.getFunctionContaining(address);
        for (Reference reference : session.program().getReferenceManager().getReferencesFrom(address)) {
            session.monitor().checkCancelled();
            Address destination = reference.getToAddress();
            Function toFunction = functions.getFunctionContaining(destination);
            JsonObject row = new JsonObject();
            row.addProperty("from", AddressCodec.format(address));
            row.addProperty("to", AddressCodec.format(destination));
            row.addProperty("ref_type", reference.getReferenceType().toString());
            addReferenceMetadata(row, reference);
            row.addProperty("from_function", fromFunction == null ? null : fromFunction.getName());
            row.addProperty("to_function", toFunction == null ? null : toFunction.getName());
            xrefs.add(row);
        }
    }

    private static void addReferenceMetadata(JsonObject row, Reference reference) {
        row.addProperty("operand_index", reference.getOperandIndex());
        row.addProperty("source", reference.getSource().name());
        row.addProperty("primary", reference.isPrimary());
    }
}
