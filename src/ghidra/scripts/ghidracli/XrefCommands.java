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

final class XrefCommands {
    private final ProgramSession session;
    private final AddressResolver addressResolver;
    private final FunctionQueries functionQueries;

    XrefCommands(ProgramSession session, AddressResolver addressResolver, FunctionQueries functionQueries) {
        this.session = session;
        this.addressResolver = addressResolver;
        this.functionQueries = functionQueries;
    }

    JsonObject handleXrefsTo(JsonObject args) {
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
            for (Reference ref : refMgr.getReferencesTo(addr)) {
                Address fromAddr = ref.getFromAddress();
                String dedupKey = fromAddr + "|" + addr + "|" + ref.getReferenceType();
                if (!seen.add(dedupKey)) continue;

                Function fromFunc = fm.getFunctionContaining(fromAddr);
                Function toFunc = fm.getFunctionContaining(addr);

                JsonObject xrefData = new JsonObject();
                xrefData.addProperty("from", fromAddr.toString());
                xrefData.addProperty("to", addr.toString());
                xrefData.addProperty("ref_type", ref.getReferenceType().toString());
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

    JsonObject handleXrefsFrom(JsonObject args) {
        if (session.program() == null) {
            return errorResult("No program loaded");
        }

        String addrStr = getArgString(args, "address");
        if (addrStr == null || addrStr.isEmpty()) {
            return errorResult("No address provided");
        }

        Address addr = addressResolver.resolveAddress(addrStr);
        if (addr == null) {
            return errorResult(functionQueries.buildFunctionTargetHint(addrStr));
        }

        JsonArray xrefs = new JsonArray();
        ReferenceManager refMgr = session.program().getReferenceManager();
        FunctionManager fm = session.program().getFunctionManager();

        // If address is a function entry point, scan the entire function body
        Function func = fm.getFunctionAt(addr);
        if (func != null) {
            ghidra.program.model.address.AddressSetView body = func.getBody();
            ghidra.program.model.address.AddressIterator addrIter = body.getAddresses(true);
            while (addrIter.hasNext()) {
                Address instrAddr = addrIter.next();
                Reference[] refs = refMgr.getReferencesFrom(instrAddr);
                for (Reference ref : refs) {
                    Address toAddr = ref.getToAddress();
                    Function toFunc = fm.getFunctionContaining(toAddr);

                    JsonObject xrefData = new JsonObject();
                    xrefData.addProperty("from", instrAddr.toString());
                    xrefData.addProperty("to", toAddr.toString());
                    xrefData.addProperty("ref_type", ref.getReferenceType().toString());
                    xrefData.addProperty("from_function", func.getName());
                    if (toFunc != null) {
                        xrefData.addProperty("to_function", toFunc.getName());
                    } else {
                        xrefData.add("to_function", JsonNull.INSTANCE);
                    }
                    xrefs.add(xrefData);
                }
            }
        } else {
            // Not a function entry point — just get refs from this single address
            Reference[] refs = refMgr.getReferencesFrom(addr);
            for (Reference ref : refs) {
                Address toAddr = ref.getToAddress();
                Function fromFunc = fm.getFunctionContaining(addr);
                Function toFunc = fm.getFunctionContaining(toAddr);

                JsonObject xrefData = new JsonObject();
                xrefData.addProperty("from", addr.toString());
                xrefData.addProperty("to", toAddr.toString());
                xrefData.addProperty("ref_type", ref.getReferenceType().toString());
                if (fromFunc != null) {
                    xrefData.addProperty("from_function", fromFunc.getName());
                } else {
                    xrefData.add("from_function", JsonNull.INSTANCE);
                }
                if (toFunc != null) {
                    xrefData.addProperty("to_function", toFunc.getName());
                } else {
                    xrefData.add("to_function", JsonNull.INSTANCE);
                }
                xrefs.add(xrefData);
            }
        }

        JsonObject result = new JsonObject();
        result.add("xrefs", xrefs);
        result.addProperty("count", xrefs.size());
        return result;
    }

    JsonObject handleXrefsList(JsonObject args) {
        if (session.program() == null) {
            return errorResult("No program loaded");
        }

        String addrStr = getArgString(args, "address");
        if (addrStr == null || addrStr.isEmpty()) {
            return errorResult("No address provided");
        }

        Address addr = addressResolver.resolveAddress(addrStr);
        if (addr == null) {
            return errorResult(functionQueries.buildFunctionTargetHint(addrStr));
        }

        JsonArray xrefs = new JsonArray();
        ReferenceManager refMgr = session.program().getReferenceManager();
        FunctionManager fm = session.program().getFunctionManager();

        // References TO the target address
        for (Reference ref : refMgr.getReferencesTo(addr)) {
            Address fromAddr = ref.getFromAddress();
            Function fromFunc = fm.getFunctionContaining(fromAddr);
            Function toFunc = fm.getFunctionContaining(addr);

            JsonObject xrefData = new JsonObject();
            xrefData.addProperty("from", fromAddr.toString());
            xrefData.addProperty("to", addr.toString());
            xrefData.addProperty("ref_type", ref.getReferenceType().toString());
            xrefData.addProperty("direction", "to");
            if (fromFunc != null) {
                xrefData.addProperty("from_function", fromFunc.getName());
            } else {
                xrefData.add("from_function", JsonNull.INSTANCE);
            }
            if (toFunc != null) {
                xrefData.addProperty("to_function", toFunc.getName());
            } else {
                xrefData.add("to_function", JsonNull.INSTANCE);
            }
            xrefs.add(xrefData);
        }

        // References FROM the target — if it's a function, scan the entire body
        Function func = fm.getFunctionAt(addr);
        if (func != null) {
            ghidra.program.model.address.AddressSetView body = func.getBody();
            ghidra.program.model.address.AddressIterator addrIter = body.getAddresses(true);
            while (addrIter.hasNext()) {
                Address instrAddr = addrIter.next();
                Reference[] refs = refMgr.getReferencesFrom(instrAddr);
                for (Reference ref : refs) {
                    Address toAddr = ref.getToAddress();
                    Function toFunc = fm.getFunctionContaining(toAddr);

                    JsonObject xrefData = new JsonObject();
                    xrefData.addProperty("from", instrAddr.toString());
                    xrefData.addProperty("to", toAddr.toString());
                    xrefData.addProperty("ref_type", ref.getReferenceType().toString());
                    xrefData.addProperty("direction", "from");
                    xrefData.addProperty("from_function", func.getName());
                    if (toFunc != null) {
                        xrefData.addProperty("to_function", toFunc.getName());
                    } else {
                        xrefData.add("to_function", JsonNull.INSTANCE);
                    }
                    xrefs.add(xrefData);
                }
            }
        } else {
            // Not a function entry — just get refs from this single address
            Reference[] refs = refMgr.getReferencesFrom(addr);
            for (Reference ref : refs) {
                Address toAddr = ref.getToAddress();
                Function fromFunc = fm.getFunctionContaining(addr);
                Function toFunc = fm.getFunctionContaining(toAddr);

                JsonObject xrefData = new JsonObject();
                xrefData.addProperty("from", addr.toString());
                xrefData.addProperty("to", toAddr.toString());
                xrefData.addProperty("ref_type", ref.getReferenceType().toString());
                xrefData.addProperty("direction", "from");
                if (fromFunc != null) {
                    xrefData.addProperty("from_function", fromFunc.getName());
                } else {
                    xrefData.add("from_function", JsonNull.INSTANCE);
                }
                if (toFunc != null) {
                    xrefData.addProperty("to_function", toFunc.getName());
                } else {
                    xrefData.add("to_function", JsonNull.INSTANCE);
                }
                xrefs.add(xrefData);
            }
        }

        JsonObject result = new JsonObject();
        result.add("xrefs", xrefs);
        result.addProperty("count", xrefs.size());
        return result;
    }
}
