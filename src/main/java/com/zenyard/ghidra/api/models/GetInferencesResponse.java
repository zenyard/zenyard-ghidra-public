package com.zenyard.ghidra.api.models;

import com.google.gson.annotations.SerializedName;
import java.util.List;

/**
 * Response from getting inferences for a revision.
 * 
 * NOTE: mirrors api.binaries.GetInferencesResponse in zenyard/src/api/binaries.py
 * Note: The API returns MaybeUnknown[Inference], but we'll handle that in deserialization.
 */
public class GetInferencesResponse {
    @SerializedName("inferences")
    private List<BaseInference> inferences;
    
    @SerializedName("cursor")
    private int cursor;
    
    @SerializedName("has_next")
    private boolean hasNext;
    
    public GetInferencesResponse() {
        // Default constructor for Gson
    }
    
    public GetInferencesResponse(List<BaseInference> inferences, int cursor, boolean hasNext) {
        this.inferences = inferences;
        this.cursor = cursor;
        this.hasNext = hasNext;
    }
    
    public List<BaseInference> getInferences() {
        return inferences;
    }
    
    public void setInferences(List<BaseInference> inferences) {
        this.inferences = inferences;
    }
    
    public int getCursor() {
        return cursor;
    }
    
    public void setCursor(int cursor) {
        this.cursor = cursor;
    }
    
    public boolean isHasNext() {
        return hasNext;
    }
    
    public void setHasNext(boolean hasNext) {
        this.hasNext = hasNext;
    }
}

