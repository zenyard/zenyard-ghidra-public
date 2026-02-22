package com.zenyard.ghidra.copilot.tools;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import dev.langchain4j.agent.tool.Tool;
import ghidra.program.model.data.ArchiveType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.SourceArchive;
import ghidra.program.model.listing.Program;

import com.zenyard.ghidra.copilot.tools.models.LocalType;
import com.zenyard.ghidra.copilot.tools.models.ToolOutput;

/**
 * Tool to get local type definitions.
 */
public class GetLocalTypesTool {
    
    private final CopilotToolContext context;
    
    public GetLocalTypesTool(CopilotToolContext context) {
        this.context = context;
    }
    
    @Tool("Returns a list of local types with their definitions")
    public ToolOutput getLocalTypes() {
        java.util.Map<String, Object> args = new java.util.HashMap<>();
        return ToolUtils.executeTool(context, "get_local_types", args, () -> {
            try {
                context.checkCancelled();

                Program program = context.getProgram();
                if (program == null) {
                    throw new ToolExecutionException("No program is currently loaded");
                }

                DataTypeManager dataTypeManager = program.getDataTypeManager();
                if (dataTypeManager == null) {
                    throw new ToolExecutionException("DataTypeManager not available");
                }

                // Deterministic map sorted by type name.
                Map<String, LocalType> byName = new TreeMap<>();
                java.util.Iterator<DataType> allTypes = dataTypeManager.getAllDataTypes();
                while (allTypes.hasNext()) {
                    context.checkCancelled();
                    DataType dataType = allTypes.next();
                    if (!isProgramLocalType(dataType)) {
                        continue;
                    }

                    String typeName = dataType.getName();
                    if (typeName == null || typeName.isBlank()) {
                        continue;
                    }

                    String definition = buildDefinition(dataType);
                    byName.putIfAbsent(typeName, new LocalType(typeName, definition));
                }

                List<LocalType> localTypes = new ArrayList<>(byName.values());
                StringBuilder output = new StringBuilder();
                for (LocalType localType : localTypes) {
                    output.append(localType.getName())
                        .append(": ")
                        .append(localType.getDefinition())
                        .append("\n");
                }
                return ToolUtils.persistLargeOutput(context, "local-types", output.toString(), localTypes.size());
            } catch (ToolExecutionException e) {
                throw e;
            } catch (Exception e) {
                throw new ToolExecutionException("Failed to get local types: " + e.getMessage(), e);
            }
        });
    }

    private boolean isProgramLocalType(DataType dataType) {
        SourceArchive sourceArchive = dataType.getSourceArchive();
        if (sourceArchive == null) {
            return false;
        }
        return sourceArchive.getArchiveType() == ArchiveType.PROGRAM;
    }

    private String buildDefinition(DataType dataType) {
        String pathName = dataType.getPathName();
        if (pathName == null || pathName.isBlank()) {
            pathName = dataType.getDisplayName();
        }
        int length = dataType.getLength();
        String sizeText = length >= 0 ? Integer.toString(length) : "dynamic";
        return pathName + " (size=" + sizeText + ")";
    }
}

