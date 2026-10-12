package ghidracli.types;

import com.google.gson.JsonObject;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidracli.session.ProgramSession;

import static ghidracli.protocol.JsonProtocol.*;

/** Explicit bit placement uses the program byte order and preserves unrelated components. */
public final class BitFieldCommands {
    private final ProgramSession session;
    private final TypeResolver resolver;

    public BitFieldCommands(ProgramSession session, TypeResolver resolver) {
        this.session = session;
        this.resolver = resolver;
    }

    public JsonObject handleCreate(JsonObject args) {
        if (session.program() == null) return errorResult("No program loaded");
        try {
            String name = getArgString(args, "type_name");
            if (name == null || name.isBlank()) throw new IllegalArgumentException("Structure name required");
            DataType target = resolver.resolveDataType(name);
            if (target == null) throw new IllegalArgumentException("Type not found: " + name);
            if (!(target instanceof Structure)) throw new IllegalArgumentException("Type is not a struct: " + name);
            String baseName = getArgString(args, "field_type");
            if (baseName == null) throw new IllegalArgumentException("field_type required");
            DataType base = resolver.resolveDataType(baseName);
            if (base == null) throw new IllegalArgumentException("Field type not found: " + baseName);
            Structure structure = (Structure) target;
            int offset = StructureFields.offset(args);
            int storage = requiredInteger(args, "storage_size");
            TypeResizeCommands.PropagationSnapshot propagation = (long) offset + storage > StructureFields.length(structure)
                ? new TypeResizeCommands.PropagationSnapshot(session, structure) : null;
            JsonObject result = BitFields.replace(structure, null, offset,
                storage, requiredInteger(args, "bit_offset"),
                requiredInteger(args, "bit_size"), base, getArgString(args, "field_name"),
                getArgString(args, "comment"));
            if (propagation != null)
                propagation.verifyInsertion(result.getAsJsonObject("after").get("ordinal").getAsInt());
            return result;
        } catch (Exception e) {
            return errorResult("Failed to create bit-field: " + e.getMessage(), e);
        }
    }

    private static int requiredInteger(JsonObject args, String name) {
        if (args == null || !args.has(name) || args.get(name).isJsonNull())
            throw new IllegalArgumentException(name + " required");
        return getNonnegativeIntArg(args, name, 0);
    }
}
