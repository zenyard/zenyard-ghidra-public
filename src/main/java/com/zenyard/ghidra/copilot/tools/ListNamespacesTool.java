package com.zenyard.ghidra.copilot.tools;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

import dev.langchain4j.agent.tool.Tool;
import ghidra.program.model.address.GlobalNamespace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;

import com.zenyard.ghidra.copilot.tools.models.PagedResults;

/**
 * Tool to list namespaces (classes/modules) in the program.
 */
public class ListNamespacesTool {
    
    private final CopilotToolContext context;
    
    public ListNamespacesTool(CopilotToolContext context) {
        this.context = context;
    }
    
    @Tool("Returns a paginated list of namespaces (classes/modules) in the program. " +
          "If next_cursor is not empty, there are more pages which can be fetched using the cursor parameter.")
    public PagedResults<String> listNamespaces(String cursor) {
        java.util.Map<String, Object> args = new java.util.HashMap<>();
        if (cursor != null) {
            args.put("cursor", cursor);
        }
        return ToolUtils.executeTool(context, "list_namespaces", args, () -> {
            try {
                context.checkCancelled();

                Program program = context.getProgram();
                if (program == null) {
                    throw new ToolExecutionException("No program is currently loaded");
                }

                SymbolTable symbolTable = program.getSymbolTable();
                SymbolIterator allSymbols = symbolTable.getAllSymbols(true);
                
                Set<String> namespaceSet = new HashSet<>();
                
                while (allSymbols.hasNext()) {
                    context.checkCancelled();
                    
                    Symbol symbol = allSymbols.next();
                    Namespace ns = symbol.getParentNamespace();
                    
                    if (ns != null && !(ns instanceof GlobalNamespace)) {
                        namespaceSet.add(ns.getName());
                    }
                }
                
                // Convert to sorted list
                List<String> allNamespaces = new ArrayList<>(new TreeSet<>(namespaceSet));
                
                // Parse cursor
                String cursorName = cursor;
                boolean pastCursor = (cursorName == null);
                
                List<String> filteredNamespaces = new ArrayList<>();
                for (String nsName : allNamespaces) {
                    // Skip until past cursor
                    if (!pastCursor) {
                        if (nsName.compareTo(cursorName) > 0) {
                            pastCursor = true;
                        } else {
                            continue;
                        }
                    }
                    filteredNamespaces.add(nsName);
                }
                
                // Paginate
                int pageSize = 200;
                List<String> pageNamespaces;
                String nextCursor = null;
                
                if (filteredNamespaces.size() > pageSize) {
                    pageNamespaces = filteredNamespaces.subList(0, pageSize);
                    nextCursor = pageNamespaces.get(pageSize - 1);
                } else {
                    pageNamespaces = filteredNamespaces;
                }
                
                return new PagedResults<>(pageNamespaces, nextCursor);
            } catch (ToolExecutionException e) {
                throw e;
            } catch (Exception e) {
                throw new ToolExecutionException("Failed to list namespaces: " + e.getMessage(), e);
            }
        });
    }
}
