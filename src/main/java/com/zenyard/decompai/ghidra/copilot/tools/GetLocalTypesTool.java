package com.zenyard.decompai.ghidra.copilot.tools;

import java.util.ArrayList;
import java.util.List;
import java.util.TreeSet;

import dev.langchain4j.agent.tool.Tool;
import ghidra.program.model.listing.Program;

import com.zenyard.decompai.ghidra.copilot.tools.models.LocalType;
import com.zenyard.decompai.ghidra.copilot.tools.models.PagedResults;

/**
 * Tool to get local type definitions.
 */
public class GetLocalTypesTool {
    
    private final CopilotToolContext context;
    
    public GetLocalTypesTool(CopilotToolContext context) {
        this.context = context;
    }
    
    @Tool("Returns a paginated list of local types with their definitions")
    public PagedResults<LocalType> getLocalTypes(String cursor) {
        try {
            context.checkCancelled();
            
            Program program = context.getProgram();
            if (program == null) {
                throw new ToolExecutionException("No program is currently loaded");
            }
            
            // Get all local type names (sorted)
            TreeSet<String> typeNames = new TreeSet<>();
            // TODO: Get actual local type names from DataTypeManager
            // DataTypeManager dataTypeManager = program.getDataTypeManager();
            // This is a simplified version - in a full implementation, we'd iterate through
            // dataTypeManager.getAllDataTypes() and filter for local types
            
            // For now, return empty list as placeholder
            List<LocalType> localTypes = new ArrayList<>();
            
            // Paginate
            int pageSize = 200;
            String nextCursor = null;
            
            // Simple cursor-based pagination by type name
            if (cursor != null && !cursor.isEmpty()) {
                // Filter types after cursor
                typeNames = new TreeSet<>(typeNames.tailSet(cursor, false));
            }
            
            List<String> pageTypeNames = new ArrayList<>();
            for (String typeName : typeNames) {
                if (pageTypeNames.size() >= pageSize) {
                    nextCursor = typeName;
                    break;
                }
                pageTypeNames.add(typeName);
            }
            
            // Create LocalType objects
            for (String typeName : pageTypeNames) {
                // TODO: Get actual type definition
                String definition = ""; // Placeholder
                localTypes.add(new LocalType(typeName, definition));
            }
            
            return new PagedResults<>(localTypes, nextCursor);
        } catch (ToolExecutionException e) {
            throw e;
        } catch (Exception e) {
            throw new ToolExecutionException("Failed to get local types: " + e.getMessage(), e);
        }
    }
}

