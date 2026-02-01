package com.zenyard.ghidra.copilot.tools.models;

import java.util.List;

/**
 * Paginated results with cursor-based pagination.
 * Mirrors the PagedResults generic class from IDA implementation.
 * 
 * @param <T> The type of items in the results
 */
public class PagedResults<T> {
    
    private final List<T> results;
    private final String nextCursor;
    
    public PagedResults(List<T> results, String nextCursor) {
        this.results = results;
        this.nextCursor = nextCursor;
    }
    
    public List<T> getResults() {
        return results;
    }
    
    public String getNextCursor() {
        return nextCursor;
    }
    
    /**
     * Map the results to a different type.
     */
    public <R> PagedResults<R> map(java.util.function.Function<T, R> mapper) {
        List<R> mappedResults = results.stream()
            .map(mapper)
            .toList();
        return new PagedResults<>(mappedResults, nextCursor);
    }
}

