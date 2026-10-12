import com.google.gson.JsonArray;
import ghidra.app.decompiler.ClangFieldToken;
import ghidra.app.decompiler.ClangNode;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.SequenceNumber;
import ghidra.program.model.pcode.Varnode;
import java.lang.reflect.Proxy;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.List;

/** Preserve native field identity while exercising pointer arithmetic before optimization. */
public class CheckSemanticFieldPointerArithmetic extends GhidraScript {
    private static void check(boolean condition, String message) {
        if (!condition) throw new IllegalStateException(message);
    }

    private static PcodeOp fieldPointer(ClangNode root) {
        ArrayDeque<ClangNode> pending = new ArrayDeque<>();
        pending.add(root);
        while (!pending.isEmpty()) {
            ClangNode node = pending.removeFirst();
            if (node instanceof ClangFieldToken field && field.getOffset() == 8
                    && field.getDataType().getPathName().equals("/Semantic/Packet")) {
                PcodeOp op = field.getPcodeOp();
                check(op != null && op.getOpcode() == PcodeOp.PTRSUB,
                    "Native array field did not retain its address operation");
                return op;
            }
            for (int i = 0; i < node.numChildren(); i++) pending.add(node.Child(i));
        }
        throw new IllegalStateException("Missing native array field token");
    }

    private static Varnode constant(HighFunction high, long value) {
        return high.newVarnode(4, high.getAddressFactory().getConstantSpace().getAddress(value));
    }

    private static void arithmetic(HighFunction high, PcodeOp origin, long forwardIndex,
            int opcode, long displacement)
            throws Exception {
        var unique = high.getAddressFactory().getUniqueSpace();
        Varnode forward = high.newVarnode(4, unique.getAddress(0x70000000));
        Varnode backward = high.newVarnode(4, unique.getAddress(0x70000010));
        List<PcodeOp> original = new ArrayList<>();
        high.getPcodeOps().forEachRemaining(original::add);
        for (PcodeOp op : original) {
            for (int i = 0; i < op.getNumInputs(); i++) {
                if (op.getInput(i) == origin.getOutput()) high.setInput(op, backward, i);
            }
        }
        // Include a legal one-past array pointer that returns before the access.
        // Keep these native AST operations detached from the saved program; a
        // subsequent optimizer pass would fold the arithmetic away.
        PcodeOp add = high.newOp(new SequenceNumber(origin.getSeqnum().getTarget(), 1000000),
            PcodeOp.PTRADD, new ArrayList<>(List.of(origin.getOutput(), constant(high, forwardIndex), constant(high, 4))),
            forward);
        ArrayList<Varnode> inputs = new ArrayList<>(List.of(forward, constant(high, displacement)));
        if (opcode == PcodeOp.PTRADD) inputs.add(constant(high, 4));
        PcodeOp subtract = high.newOp(new SequenceNumber(origin.getSeqnum().getTarget(), 1000001),
            opcode, inputs, backward);
        high.insertAfter(add, origin);
        high.insertAfter(subtract, add);
    }

    public void run() throws Exception {
        Class<?> caller = StackWalker.getInstance(StackWalker.Option.RETAIN_CLASS_REFERENCE)
            .walk(frames -> frames.map(StackWalker.StackFrame::getDeclaringClass)
                .filter(type -> type.getSimpleName().equals("ScriptCommands")
                    && type.getPackageName().equals("ghidracli.script"))
                .findFirst().orElseThrow());
        ClassLoader loader = caller.getClassLoader();
        String prefix = caller.getPackageName().substring(0, caller.getPackageName().lastIndexOf('.') + 1);
        Class<?> sessionClass = loader.loadClass(prefix + "session.ProgramSession");
        Class<?> accessClass = loader.loadClass(prefix + "session.ScriptAccess");
        Object access = Proxy.newProxyInstance(loader, new Class<?>[] {accessClass},
            (proxy, method, args) -> {
                switch (method.getName()) {
                    case "program": return currentProgram;
                    case "monitor": return monitor;
                    default: throw new UnsupportedOperationException(method.getName());
                }
            });
        Object session = sessionClass.getConstructor(accessClass).newInstance(access);
        Class<?> fieldsClass = loader.loadClass(prefix + "analysis.FieldUses");
        var find = fieldsClass.getDeclaredMethod("find", sessionClass, Function.class,
            DecompileResults.class, ghidra.program.model.data.DataTypeComponent.class);
        find.setAccessible(true);
        Structure packet = (Structure) currentProgram.getDataTypeManager().getDataType("/Semantic/Packet");
        long modification = currentProgram.getModificationNumber();
        DecompInterface engine = new DecompInterface();
        check(engine.openProgram(currentProgram), "Cannot open native decompiler");
        try {
            int[] opcodes = {PcodeOp.PTRADD, PcodeOp.INT_ADD, PcodeOp.INT_SUB,
                PcodeOp.INT_ADD, PcodeOp.PTRADD, PcodeOp.PTRADD};
            long[] forwardIndices = {1, 1, 1, 1, 2, 2};
            long[] offsets = {0xffffffffL, 0xfffffffcL, 4, 0xfffffff8L,
                0xfffffffeL, 0xffffffffL};
            for (long entry : new long[] {0x1280, 0x15c0}) {
                Function function = getFunctionAt(toAddr(entry));
                for (int i = 0; i < opcodes.length; i++) {
                    DecompileResults results = engine.decompileFunction(function, 30, monitor);
                    check(results.decompileCompleted(), results.getErrorMessage());
                    arithmetic(results.getHighFunction(), fieldPointer(results.getCCodeMarkup()),
                        forwardIndices[i], opcodes[i], offsets[i]);
                    Object findings = find.invoke(null, session, function, results, packet.getComponentAt(8));
                    var usesMethod = findings.getClass().getDeclaredMethod("uses");
                    usesMethod.setAccessible(true);
                    JsonArray uses = (JsonArray) usesMethod.invoke(findings);
                    check(uses.size() == 1, "Unexpected arithmetic field uses: " + uses);
                    String expected = i == 3 || i == 5 ? "address" : entry == 0x1280 ? "read" : "write";
                    check(uses.get(0).getAsJsonObject().get("access").getAsString().equals(expected),
                        "Incorrect field access after +" + forwardIndices[i] + " elements and "
                            + PcodeOp.getMnemonic(opcodes[i]) + ": " + uses);
                    if (i == 5) {
                        var unresolvedMethod = findings.getClass().getDeclaredMethod("unresolved");
                        unresolvedMethod.setAccessible(true);
                        JsonArray unresolved = (JsonArray) unresolvedMethod.invoke(findings);
                        boolean diagnosed = false;
                        for (var row : unresolved) {
                            diagnosed |= row.getAsJsonObject().get("reason").getAsString()
                                .equals("memory_access_extends_beyond_field");
                        }
                        check(diagnosed,
                            "One-past dereference lacks its field-bound diagnostic: " + unresolved);
                    }
                }
            }
            check(currentProgram.getModificationNumber() == modification,
                "Detached arithmetic probe changed the saved program");
        } finally {
            engine.dispose();
        }
    }
}
