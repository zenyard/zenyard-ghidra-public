package com.zenyard.ghidra.api.models;

import com.google.gson.annotations.SerializedName;
import java.util.List;

/**
 * Parameters for adding objects to the current revision.
 * 
 * NOTE: mirrors binary.api.AddObjectsToCurrentRevisionParams in zenyard/src/binary/api.py
 */
public class AddObjectsToCurrentRevisionParams {
    @SerializedName("objects")
    private List<BaseObject> objects;
    
    public AddObjectsToCurrentRevisionParams() {
        // Default constructor for Gson
    }
    
    public AddObjectsToCurrentRevisionParams(List<BaseObject> objects) {
        this.objects = objects;
    }
    
    public List<BaseObject> getObjects() {
        return objects;
    }
    
    public void setObjects(List<BaseObject> objects) {
        this.objects = objects;
    }
}

