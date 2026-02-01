package com.zenyard.ghidra.api.models;

import com.google.gson.annotations.SerializedName;

/**
 * Parameters for creating a revision.
 * 
 * NOTE: mirrors binary.api.CreateRevisionParams in zenyard/src/binary/api.py
 */
public class CreateRevisionParams {
    @SerializedName("number")
    private int number;
    
    public CreateRevisionParams() {
        // Default constructor for Gson
    }
    
    public CreateRevisionParams(int number) {
        this.number = number;
    }
    
    public int getNumber() {
        return number;
    }
    
    public void setNumber(int number) {
        this.number = number;
    }
}

