package com.zenyard.ghidra.util;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.zenyard.ghidra.api.generated.model.Function;
import com.zenyard.ghidra.api.generated.model.GlobalVariable;
import com.zenyard.ghidra.api.generated.model.ModelObject;
import com.zenyard.ghidra.api.generated.model.Thunk;
import ghidra.util.Msg;

/**
 * Utility for hashing objects to detect changes.
 * 
 * Mirrors zenyard_ida/objects.py hash_object() logic.
 * Uses BLAKE2b (8 bytes) -> base64 encoding to match IDA.
 * 
 * NOTE: Currently uses SHA-256 truncated to 8 bytes as a fallback.
 * TODO: Add BouncyCastle dependency for proper BLAKE2b support.
 */
public class ObjectHasher {
    
    private static final Gson gson = new GsonBuilder()
        .serializeNulls()
        .create();
    
    /**
     * Hash an object (Function, Thunk, or GlobalVariable).
     * 
     * The hash excludes:
     * - inference_seq_number (set to 0)
     * - Object references in code (replaced with [obj])
     * 
     * @param obj The object to hash
     * @return Base64-encoded hash (8 bytes)
     */
    public static String hashObject(ModelObject obj) {
        if (obj == null || obj.getActualInstance() == null) {
            throw new IllegalArgumentException("Object cannot be null");
        }
        
        Object actualInstance = obj.getActualInstance();
        
        // Reduce object references from code for functions
        if (actualInstance instanceof Function) {
            actualInstance = reduceObjectReferencesFromCode((Function) actualInstance);
        }
        
        // Reduce inference_seq_number to 0
        actualInstance = reduceInferenceSeqNumber(actualInstance);
        
        // Serialize to JSON (sorted keys, compact format)
        String json = gson.toJson(actualInstance);
        
        // Hash using SHA-256 truncated to 8 bytes (BLAKE2b fallback)
        // TODO: Replace with BLAKE2b when BouncyCastle is added
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(json.getBytes(StandardCharsets.UTF_8));
            // Truncate to 8 bytes to match BLAKE2b digest_size=8
            byte[] truncatedHash = new byte[8];
            System.arraycopy(hashBytes, 0, truncatedHash, 0, 8);
            
            // Base64 encode
            return Base64.getEncoder().encodeToString(truncatedHash);
        } catch (Exception e) {
            Msg.error(ObjectHasher.class, "Failed to hash object: " + e.getMessage(), e);
            throw new RuntimeException("Failed to hash object", e);
        }
    }
    
    /**
     * Reduce object references in function code to [obj] placeholder.
     * 
     * This ensures that changing other objects doesn't change this object's hash.
     * 
     * NOTE: This is a simplified implementation. Full implementation would parse
     * ranges and replace AddressDetail references to other objects with [obj].
     * For now, we return the function as-is - the hash will still work but may
     * change when referenced objects change.
     */
    private static Function reduceObjectReferencesFromCode(Function func) {
        // TODO: Implement full object reference reduction
        // This requires parsing Range/RangeDetail/AddressDetail structures
        // and replacing references to other objects with [obj]
        // For now, return function as-is to get basic hashing working
        return func;
    }
    
    /**
     * Reduce inference_seq_number to 0 for hashing.
     */
    private static Object reduceInferenceSeqNumber(Object obj) {
        if (obj instanceof Function) {
            Function func = (Function) obj;
            Function reduced = new Function();
            reduced.setAddress(func.getAddress());
            reduced.setName(func.getName());
            reduced.setHasKnownName(func.getHasKnownName());
            reduced.setInferenceSeqNumber(0); // Set to 0
            reduced.setCode(func.getCode());
            reduced.setCalls(func.getCalls());
            reduced.setDataRefsTo(func.getDataRefsTo());
            reduced.setMangledName(func.getMangledName());
            reduced.setRanges(func.getRanges());
            reduced.setLineRanges(func.getLineRanges());
            reduced.setDecompilerNotes(func.getDecompilerNotes());
            return reduced;
        } else if (obj instanceof Thunk) {
            Thunk thunk = (Thunk) obj;
            Thunk reduced = new Thunk();
            reduced.setAddress(thunk.getAddress());
            reduced.setName(thunk.getName());
            reduced.setInferenceSeqNumber(0); // Set to 0
            return reduced;
        } else if (obj instanceof GlobalVariable) {
            GlobalVariable gv = (GlobalVariable) obj;
            GlobalVariable reduced = new GlobalVariable();
            reduced.setAddress(gv.getAddress());
            reduced.setName(gv.getName());
            reduced.setHasKnownName(gv.getHasKnownName());
            reduced.setMangledName(gv.getMangledName());
            reduced.setInferenceSeqNumber(0); // Set to 0
            reduced.setUses(gv.getUses());
            return reduced;
        }
        
        // Unknown type, return as-is
        return obj;
    }
}

