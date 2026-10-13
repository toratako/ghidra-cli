
import ghidra.app.script.GhidraScript;
import ghidra.docking.settings.FormatSettingsDefinition;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
public class CheckSavedUnionSettings extends GhidraScript {
    public void run() throws Exception {
        Object consumer = new Object();
        Program saved = (Program) currentProgram.getDomainFile()
            .getReadOnlyDomainObject(consumer, DomainFile.DEFAULT_VERSION, monitor);
        try {
            String[] args = getScriptArgs();
            var union = (Union) saved.getDataTypeManager().getDataType("/" + args[0]);
            boolean packed = args[0].equals("Packed");
            if (union.isPackingEnabled() != packed || !union.getDescription().equals("recovered layout"))
                throw new IllegalStateException("Union layout metadata changed");
            if (packed && (union.getExplicitPackingValue() != 2
                    || union.getExplicitMinimumAlignment() != 16 || union.getAlignment() != 16))
                throw new IllegalStateException("Packing or minimum alignment changed");
            for (int i = 1; i < args.length; i++) {
                DataTypeComponent field = null;
                for (var candidate : union.getComponents())
                    if (args[i].equals(candidate.getFieldName())) field = candidate;
                if (field == null) throw new IllegalStateException("Missing member " + args[i]);
                if (FormatSettingsDefinition.DEF.getChoice(field.getDefaultSettings())
                        != FormatSettingsDefinition.DECIMAL
                        || EndianSettingsDefinition.DEF.getChoice(field.getDefaultSettings())
                        != EndianSettingsDefinition.BIG)
                    throw new IllegalStateException("Member settings changed: " + args[i]);
            }
            var holder = (Structure) saved.getDataTypeManager().getDataType("/" + args[0] + "Holder");
            var tail = holder.getComponentAt(16);
            if (!tail.getFieldName().equals("tail") || tail.getLength() != 4
                    || holder.getComponentAt(0).getDataType() != union
                    || FormatSettingsDefinition.DEF.getChoice(tail.getDefaultSettings())
                        != FormatSettingsDefinition.BINARY)
                throw new IllegalStateException("Parent field or its settings changed");
        } finally { saved.release(consumer); }
    }
}
