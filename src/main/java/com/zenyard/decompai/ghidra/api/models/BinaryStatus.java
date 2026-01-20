package com.zenyard.decompai.ghidra.api.models;

import com.google.gson.annotations.SerializedName;
import java.util.List;

/**
 * Detailed status of binary analysis.
 * 
 * NOTE: mirrors binary.api.BinaryStatus in decompai/src/binary/api.py
 */
public class BinaryStatus {
    @SerializedName("revision_analyses")
    private List<RevisionAnalysisStatus> revisionAnalyses;
    
    public BinaryStatus() {
        // Default constructor for Gson
    }
    
    public BinaryStatus(List<RevisionAnalysisStatus> revisionAnalyses) {
        this.revisionAnalyses = revisionAnalyses;
    }
    
    public List<RevisionAnalysisStatus> getRevisionAnalyses() {
        return revisionAnalyses;
    }
    
    public void setRevisionAnalyses(List<RevisionAnalysisStatus> revisionAnalyses) {
        this.revisionAnalyses = revisionAnalyses;
    }
}

