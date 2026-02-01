package com.zenyard.ghidra.copilot.tools;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Predicate;
import java.util.regex.Pattern;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;

import com.zenyard.ghidra.copilot.tools.models.Function;
import com.zenyard.ghidra.copilot.tools.models.PagedResults;

/**
 * Helper for cursor-based pagination of functions.
 * Mirrors the pagination logic from IDA implementation.
 */
public class PaginationHelper {
    
    private static final int DEFAULT_PAGE_SIZE = 200;
    private static final int MAX_PAGES = 20;
    
    /**
     * Paginate functions with optional filter.
     */
    public static PagedResults<Function> paginateFunctions(
            Program program,
            String cursor,
            String filter,
            java.util.function.Function<ghidra.program.model.listing.Function, com.zenyard.ghidra.copilot.tools.models.Function> mapper) {
        
        return paginateFunctions(program, cursor, filter, mapper, null);
    }
    
    /**
     * Paginate functions with optional filter and predicate.
     */
    public static PagedResults<Function> paginateFunctions(
            Program program,
            String cursor,
            String filter,
            java.util.function.Function<ghidra.program.model.listing.Function, com.zenyard.ghidra.copilot.tools.models.Function> mapper,
            Predicate<ghidra.program.model.listing.Function> additionalFilter) {
        
        if (program == null) {
            throw new ToolExecutionException("No program is currently loaded");
        }
        
        FunctionManager functionManager = program.getFunctionManager();
        FunctionIterator functions = functionManager.getFunctions(true);
        
        // Parse cursor address
        Address startAddress = null;
        if (cursor != null && !cursor.isEmpty()) {
            startAddress = ToolUtils.parseAddress(program, cursor);
        }
        
        // Compile filter pattern if provided
        Pattern filterPattern = null;
        if (filter != null && !filter.isEmpty()) {
            try {
                filterPattern = Pattern.compile(filter);
            } catch (Exception e) {
                throw new ToolExecutionException("Invalid regex pattern: " + e.getMessage());
            }
        }
        
        // Collect matching functions
        List<ghidra.program.model.listing.Function> matchingFunctions = new ArrayList<>();
        boolean pastCursor = (startAddress == null);
        
        for (ghidra.program.model.listing.Function func : functions) {
            // Skip until we're past the cursor
            if (!pastCursor) {
                if (func.getEntryPoint().compareTo(startAddress) > 0) {
                    pastCursor = true;
                } else {
                    continue;
                }
            }
            
            // Apply filter
            if (filterPattern != null) {
                String funcName = func.getName();
                if (funcName == null || !filterPattern.matcher(funcName).find()) {
                    continue;
                }
            }
            
            // Apply additional filter if provided
            if (additionalFilter != null && !additionalFilter.test(func)) {
                continue;
            }
            
            matchingFunctions.add(func);
            
            // Limit to prevent excessive memory usage
            if (matchingFunctions.size() > DEFAULT_PAGE_SIZE * MAX_PAGES) {
                throw new ToolExecutionException(
                    "Too many pages for the current operation. Try to narrow down your search.");
            }
        }
        
        // Take page_size + 1 to determine if there's a next page
        int pageSize = DEFAULT_PAGE_SIZE;
        List<ghidra.program.model.listing.Function> pageFunctions;
        String nextCursor = null;
        
        if (matchingFunctions.size() > pageSize) {
            pageFunctions = matchingFunctions.subList(0, pageSize);
            // Set next cursor to the last function's address
            nextCursor = ToolUtils.formatAddress(pageFunctions.get(pageSize - 1).getEntryPoint());
        } else {
            pageFunctions = matchingFunctions;
        }
        
        // Map to tool Function objects
        List<Function> results = new ArrayList<>();
        for (ghidra.program.model.listing.Function func : pageFunctions) {
            results.add(mapper.apply(func));
        }
        
        return new PagedResults<>(results, nextCursor);
    }
}

