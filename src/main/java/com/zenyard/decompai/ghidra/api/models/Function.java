package com.zenyard.decompai.ghidra.api.models;

import com.google.gson.annotations.SerializedName;
import java.util.List;

/**
 * Represents a function object.
 * 
 * NOTE: mirrors models.binary.Function in decompai/src/models/binary.py
 */
public class Function extends BaseObject {
    @SerializedName("code")
    private String code;
    
    @SerializedName("calls")
    private List<Address> calls;
    
    @SerializedName("data_refs_to")
    private List<Address> dataRefsTo;
    
    @SerializedName("mangled_name")
    private String mangledName;
    
    @SerializedName("ranges")
    private List<Range> ranges;
    
    @SerializedName("line_ranges")
    private List<LineRange> lineRanges;
    
    @SerializedName("decompiler_notes")
    private List<DecompilerNote> decompilerNotes;
    
    public Function() {
        super();
        setType("function");
    }
    
    public Function(Address address, String name, boolean hasKnownName, int inferenceSeqNumber,
                    String code, List<Address> calls, List<Address> dataRefsTo, String mangledName,
                    List<Range> ranges, List<LineRange> lineRanges, List<DecompilerNote> decompilerNotes) {
        super(address, "function", name, hasKnownName, inferenceSeqNumber);
        this.code = code;
        this.calls = calls;
        this.dataRefsTo = dataRefsTo;
        this.mangledName = mangledName;
        this.ranges = ranges;
        this.lineRanges = lineRanges;
        this.decompilerNotes = decompilerNotes;
    }
    
    public String getCode() {
        return code;
    }
    
    public void setCode(String code) {
        this.code = code;
    }
    
    public List<Address> getCalls() {
        return calls;
    }
    
    public void setCalls(List<Address> calls) {
        this.calls = calls;
    }
    
    public List<Address> getDataRefsTo() {
        return dataRefsTo;
    }
    
    public void setDataRefsTo(List<Address> dataRefsTo) {
        this.dataRefsTo = dataRefsTo;
    }
    
    public String getMangledName() {
        return mangledName;
    }
    
    public void setMangledName(String mangledName) {
        this.mangledName = mangledName;
    }
    
    public List<Range> getRanges() {
        return ranges;
    }
    
    public void setRanges(List<Range> ranges) {
        this.ranges = ranges;
    }
    
    public List<LineRange> getLineRanges() {
        return lineRanges;
    }
    
    public void setLineRanges(List<LineRange> lineRanges) {
        this.lineRanges = lineRanges;
    }
    
    public List<DecompilerNote> getDecompilerNotes() {
        return decompilerNotes;
    }
    
    public void setDecompilerNotes(List<DecompilerNote> decompilerNotes) {
        this.decompilerNotes = decompilerNotes;
    }
}

