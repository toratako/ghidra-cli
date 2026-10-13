
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import java.io.File;

public class ChangeArchiveMetadata extends GhidraScript {
    @Override
    public void run() throws Exception {
        var archive = FileDataTypeManager.openFileArchive(new File(getScriptArgs()[0]), true);
        try {
            int transaction = archive.startTransaction("Update archive metadata");
            try {
                var node = (Structure) archive.getDataType("/Gdt/Node");
                node.setDescription("updated node description");
                var callback = (FunctionDefinition) archive.getDataType("/Gdt/Callback");
                var parameter = callback.getArguments()[0];
                callback.setArguments(new ParameterDefinitionImpl(parameter.getName(),
                    parameter.getDataType(), "updated parameter comment"));
            } finally { archive.endTransaction(transaction, true); }
            archive.save();
        } finally { archive.close(); }
    }
}
