package ghidracli.types;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.TypeDef;
import ghidra.util.exception.CancelledException;
import ghidracli.session.ProgramSession;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.Set;

/** Request-local registered identity matching through declaration wrappers. */
public final class TypeUseMatcher {
    private final ProgramSession session;
    private final DataTypeManager manager;
    private final DataType target;

    public TypeUseMatcher(ProgramSession session, DataType target) {
        this.session = session;
        this.manager = session.program().getDataTypeManager();
        this.target = target;
        if (target.getDataTypeManager() != manager || !manager.contains(target)) {
            throw new IllegalArgumentException("Type-use target must be a registered program type");
        }
    }

    public JsonObject match(DataType declared) throws CancelledException {
        JsonArray wrappers = new JsonArray();
        Set<DataType> visited = Collections.newSetFromMap(new IdentityHashMap<>());
        DataType current = declared;
        while (current != null && visited.add(current)) {
            session.monitor().checkCancelled();
            if (sameType(current)) {
                JsonObject row = new JsonObject();
                row.addProperty("type", declared.getDisplayName());
                row.addProperty("type_path", declared.getPathName());
                row.add("wrappers", wrappers);
                return row;
            }
            JsonObject wrapper = new JsonObject();
            wrapper.addProperty("type_path", current.getPathName());
            if (current instanceof TypeDef alias) {
                wrapper.addProperty("kind", "typedef");
                current = alias.getDataType();
            } else if (current instanceof Pointer pointer) {
                wrapper.addProperty("kind", "pointer");
                wrapper.addProperty("size", pointer.getLength());
                current = pointer.getDataType();
            } else if (current instanceof Array array) {
                wrapper.addProperty("kind", "array");
                wrapper.addProperty("count", array.getNumElements());
                current = array.getDataType();
            } else {
                break;
            }
            wrappers.add(wrapper);
        }
        return null;
    }

    public boolean sameType(DataType candidate) throws CancelledException {
        Set<DataType> visited = Collections.newSetFromMap(new IdentityHashMap<>());
        DataType expected = target;
        while (candidate != null && expected != null && visited.add(candidate)) {
            session.monitor().checkCancelled();
            // Numeric IDs are only meaningful within their owning manager.
            if (candidate.getDataTypeManager() != manager) return false;
            if (manager.contains(candidate)) {
                return manager.contains(expected) && manager.getID(candidate) == manager.getID(expected);
            }
            // The decompiler reconstructs anonymous pointer/array wrappers.
            // Match their shape only until reaching registered leaf identity;
            // never substitute same-name or structurally equivalent composites.
            if (candidate instanceof Pointer actual && expected instanceof Pointer wanted) {
                if (actual.getLength() != wanted.getLength()) return false;
                candidate = actual.getDataType();
                expected = wanted.getDataType();
                if (candidate == null || expected == null) return candidate == expected;
            } else if (candidate instanceof Array actual && expected instanceof Array wanted) {
                if (actual.getNumElements() != wanted.getNumElements()
                        || actual.getElementLength() != wanted.getElementLength()) return false;
                candidate = actual.getDataType();
                expected = wanted.getDataType();
            } else {
                return false;
            }
        }
        return false;
    }
}
