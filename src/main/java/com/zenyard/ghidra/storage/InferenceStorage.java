package com.zenyard.ghidra.storage;

import java.io.IOException;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.TypeAdapter;
import com.google.gson.TypeAdapterFactory;
import com.google.gson.reflect.TypeToken;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;
import com.google.gson.stream.JsonWriter;

import org.openapitools.jackson.nullable.JsonNullable;

import com.zenyard.ghidra.api.generated.model.ParameterType;
import com.zenyard.ghidra.api.generated.model.ParametersMapping;
import com.zenyard.ghidra.api.generated.model.ReturnType;
import com.zenyard.ghidra.api.generated.model.StructDefinition;
import com.zenyard.ghidra.api.generated.model.VariablesMapping;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;

/**
 * Higher-level abstraction over ZenyardProgramProperties for managing storage of 
 * inferences, variable mappings, and analysis state.
 * 
 * Uses JSON serialization (Gson) for complex data structures.
 * 
 * NOTE: This replaces the complex storage system in zenyard_ida/storage.py
 * which had to work around IDA's 1024-byte blob limit.
 */
public class InferenceStorage {
    
    private static final String INFERENCE_PREFIX = "inference.";
    private static final String VARIABLE_PREFIX = "variable.";
    private static final String STRUCT_PREFIX = "struct.";
    private static final String INFERRED_TYPE_PREFIX = "inferred_type.";
    private static final String ANALYSIS_STATE_KEY = "analysis_state";
    private static final String STRUCT_REGISTRY_KEY = STRUCT_PREFIX + "registry.definitions";
    private static final String STRUCT_EFFECTIVE_NAMES_KEY = STRUCT_PREFIX + "effective_names";
    private static final String DEFERRED_TYPE_INFERENCES_KEY = INFERENCE_PREFIX + "deferred.type_inferences";
    private static final String VARIABLE_IDENTITIES_PREFIX = VARIABLE_PREFIX + "identity.";
    private static final String APPLIED_VARIABLE_RENAMES_PREFIX = VARIABLE_PREFIX + "applied_renames.";
    
    private final ZenyardProgramProperties properties;
    private final Gson gson;
    
    public InferenceStorage(Program program) {
        this.properties = new ZenyardProgramProperties(program);
        this.gson = new GsonBuilder()
            .setPrettyPrinting()
            .registerTypeAdapterFactory(new JsonNullableTypeAdapterFactory())
            .create();
    }

    /**
     * Gson TypeAdapterFactory for Jackson's {@code JsonNullable<T>}.
     * <p>
     * Serializes present values as the unwrapped value and absent/undefined as JSON null.
     * Deserializes JSON null back to {@code JsonNullable.undefined()} and non-null values
     * to {@code JsonNullable.of(value)}.
     * <p>
     * Without this adapter, Gson cannot round-trip {@code JsonNullable<UUID>} fields
     * correctly, causing silent data loss (e.g., struct_id references in FieldDefinition).
     */
    @SuppressWarnings("unchecked")
    private static class JsonNullableTypeAdapterFactory implements TypeAdapterFactory {
        @Override
        public <T> TypeAdapter<T> create(Gson gson, TypeToken<T> typeToken) {
            if (!JsonNullable.class.isAssignableFrom(typeToken.getRawType())) {
                return null;
            }
            Type innerType = Object.class;
            Type type = typeToken.getType();
            if (type instanceof ParameterizedType) {
                java.lang.reflect.Type[] typeArgs = ((ParameterizedType) type).getActualTypeArguments();
                if (typeArgs.length > 0) {
                    innerType = typeArgs[0];
                }
            }
            TypeAdapter<?> innerAdapter = gson.getAdapter(TypeToken.get(innerType));
            return (TypeAdapter<T>) new JsonNullableTypeAdapter<>(innerAdapter);
        }
    }

    private static class JsonNullableTypeAdapter<V> extends TypeAdapter<JsonNullable<V>> {
        private final TypeAdapter<V> innerAdapter;

        @SuppressWarnings("unchecked")
        JsonNullableTypeAdapter(TypeAdapter<?> innerAdapter) {
            this.innerAdapter = (TypeAdapter<V>) innerAdapter;
        }

        @Override
        public void write(JsonWriter out, JsonNullable<V> value) throws IOException {
            if (value == null || !value.isPresent()) {
                out.nullValue();
            } else {
                innerAdapter.write(out, value.get());
            }
        }

        @Override
        public JsonNullable<V> read(JsonReader in) throws IOException {
            if (in.peek() == JsonToken.NULL) {
                in.nextNull();
                return JsonNullable.undefined();
            }
            V inner = innerAdapter.read(in);
            return JsonNullable.of(inner);
        }
    }
    
    /**
     * Data class for inference information.
     */
    public static class InferenceData {
        private String inferenceId;
        private String type;
        private Map<String, Object> data;
        
        public InferenceData() {
            this.data = new HashMap<>();
        }
        
        public InferenceData(String inferenceId, String type, Map<String, Object> data) {
            this.inferenceId = inferenceId;
            this.type = type;
            this.data = data != null ? data : new HashMap<>();
        }
        
        public String getInferenceId() {
            return inferenceId;
        }
        
        public void setInferenceId(String inferenceId) {
            this.inferenceId = inferenceId;
        }
        
        public String getType() {
            return type;
        }
        
        public void setType(String type) {
            this.type = type;
        }
        
        public Map<String, Object> getData() {
            return data;
        }
        
        public void setData(Map<String, Object> data) {
            this.data = data;
        }
    }
    
    /**
     * Data class for variable mapping.
     */
    public static class VariableMapping {
        private Address address;
        private String originalName;
        private String inferredName;
        
        public VariableMapping() {
        }
        
        public VariableMapping(Address address, String originalName, String inferredName) {
            this.address = address;
            this.originalName = originalName;
            this.inferredName = inferredName;
        }
        
        public Address getAddress() {
            return address;
        }
        
        public void setAddress(Address address) {
            this.address = address;
        }
        
        public String getOriginalName() {
            return originalName;
        }
        
        public void setOriginalName(String originalName) {
            this.originalName = originalName;
        }
        
        public String getInferredName() {
            return inferredName;
        }
        
        public void setInferredName(String inferredName) {
            this.inferredName = inferredName;
        }
    }
    
    /**
     * Data class for analysis state.
     */
    public static class AnalysisState {
        private boolean uploadComplete;
        private boolean analysisComplete;
        private String status;
        
        public AnalysisState() {
            this.uploadComplete = false;
            this.analysisComplete = false;
            this.status = "pending";
        }
        
        public AnalysisState(boolean uploadComplete, boolean analysisComplete, String status) {
            this.uploadComplete = uploadComplete;
            this.analysisComplete = analysisComplete;
            this.status = status;
        }
        
        public boolean isUploadComplete() {
            return uploadComplete;
        }
        
        public void setUploadComplete(boolean uploadComplete) {
            this.uploadComplete = uploadComplete;
        }
        
        public boolean isAnalysisComplete() {
            return analysisComplete;
        }
        
        public void setAnalysisComplete(boolean analysisComplete) {
            this.analysisComplete = analysisComplete;
        }
        
        public String getStatus() {
            return status;
        }
        
        public void setStatus(String status) {
            this.status = status;
        }
    }

    /**
     * Deferred function type inference for retry when a struct is not yet available.
     */
    public static class DeferredTypeInferenceRecord {
        private String id;
        private String kind;
        private int attempts;
        private ParameterType parameterType;
        private ReturnType returnType;

        public DeferredTypeInferenceRecord() {
        }

        public DeferredTypeInferenceRecord(
            String id,
            String kind,
            int attempts,
            ParameterType parameterType,
            ReturnType returnType
        ) {
            this.id = id;
            this.kind = kind;
            this.attempts = attempts;
            this.parameterType = parameterType;
            this.returnType = returnType;
        }

        public String getId() {
            return id;
        }

        public String getKind() {
            return kind;
        }

        public int getAttempts() {
            return attempts;
        }

        public ParameterType getParameterType() {
            return parameterType;
        }

        public ReturnType getReturnType() {
            return returnType;
        }
    }

    /**
     * Stable identity for a local variable storage location.
     */
    public static class VariableStorageIdentity {
        private String kind;
        private String location;
        private int size;

        public VariableStorageIdentity() {
        }

        public VariableStorageIdentity(String kind, String location, int size) {
            this.kind = kind;
            this.location = location;
            this.size = size;
        }

        public String getKind() {
            return kind;
        }

        public void setKind(String kind) {
            this.kind = kind;
        }

        public String getLocation() {
            return location;
        }

        public void setLocation(String location) {
            this.location = location;
        }

        public int getSize() {
            return size;
        }

        public void setSize(int size) {
            this.size = size;
        }

        public String asKey() {
            return (kind != null ? kind : "unknown") + ":" + (location != null ? location : "unknown") + ":" + size;
        }
    }
    
    /**
     * Store an inference.
     */
    public void storeInference(String inferenceId, InferenceData data) {
        String key = INFERENCE_PREFIX + inferenceId;
        String json = gson.toJson(data);
        properties.setString(key, json);
    }
    
    /**
     * Get an inference.
     */
    public InferenceData getInference(String inferenceId) {
        String key = INFERENCE_PREFIX + inferenceId;
        String json = properties.getString(key);
        if (json == null || json.isEmpty()) {
            return null;
        }
        return gson.fromJson(json, InferenceData.class);
    }
    
    /**
     * Store a variable mapping.
     */
    public void storeVariableMapping(Address address, String variableName, String inferredName) {
        String key = VARIABLE_PREFIX + address.toString();
        VariableMapping mapping = new VariableMapping(address, variableName, inferredName);
        String json = gson.toJson(mapping);
        properties.setString(key, json);
    }
    
    /**
     * Get variable mappings.
     */
    public Map<Address, VariableMapping> getVariableMappings() {
        Map<Address, VariableMapping> mappings = new HashMap<>();
        // Note: In a full implementation, we would iterate over all properties
        // with the VARIABLE_PREFIX. For now, this is a placeholder structure.
        // We would need to extend ZenyardProgramProperties to support iteration.
        return mappings;
    }
    
    /**
     * Store analysis state.
     */
    public void storeAnalysisState(AnalysisState state) {
        String json = gson.toJson(state);
        properties.setString(ANALYSIS_STATE_KEY, json);
    }
    
    /**
     * Get analysis state.
     */
    public AnalysisState getAnalysisState() {
        String json = properties.getString(ANALYSIS_STATE_KEY);
        if (json == null || json.isEmpty()) {
            return new AnalysisState();
        }
        return gson.fromJson(json, AnalysisState.class);
    }
    
    /**
     * Store last variables mapping for an address.
     */
    public void storeLastVariablesMapping(Address address, VariablesMapping mapping) {
        String key = VARIABLE_PREFIX + "last." + address.toString();
        String json = gson.toJson(mapping);
        properties.setString(key, json);
    }
    
    /**
     * Get last variables mapping for an address.
     */
    public VariablesMapping getLastVariablesMapping(Address address) {
        String key = VARIABLE_PREFIX + "last." + address.toString();
        String json = properties.getString(key);
        if (json == null || json.isEmpty()) {
            return null;
        }
        return gson.fromJson(json, VariablesMapping.class);
    }

    /**
     * Check if a stored variables mapping exists for an address (cheap, no JSON parsing).
     */
    public boolean hasStoredVariablesMapping(Address address) {
        String key = VARIABLE_PREFIX + "last." + address.toString();
        String json = properties.getString(key);
        return json != null && !json.isEmpty();
    }

    /**
     * Persist renames that were actually applied to variables for this function.
     * Entries are merged with existing data to keep rename history across batches.
     */
    public void storeAppliedVariableRenames(Address address, Map<String, String> appliedRenames) {
        if (address == null || appliedRenames == null || appliedRenames.isEmpty()) {
            return;
        }
        Map<String, String> merged = getAppliedVariableRenames(address);
        merged.putAll(appliedRenames);
        properties.setString(APPLIED_VARIABLE_RENAMES_PREFIX + address.toString(), gson.toJson(merged));
    }

    /**
     * Get persisted successfully-applied variable renames for a function.
     */
    public Map<String, String> getAppliedVariableRenames(Address address) {
        if (address == null) {
            return new HashMap<>();
        }
        String json = properties.getString(APPLIED_VARIABLE_RENAMES_PREFIX + address.toString());
        if (json == null || json.isEmpty()) {
            return new HashMap<>();
        }
        Type mapType = new TypeToken<Map<String, String>>() { }.getType();
        Map<String, String> renames = gson.fromJson(json, mapType);
        return renames != null ? renames : new HashMap<>();
    }

    /**
     * Check if successfully-applied variable rename data exists for a function.
     */
    public boolean hasAppliedVariableRenames(Address address) {
        if (address == null) {
            return false;
        }
        String json = properties.getString(APPLIED_VARIABLE_RENAMES_PREFIX + address.toString());
        return json != null && !json.isEmpty();
    }
    
    /**
     * Store last parameters mapping for an address.
     */
    public void storeLastParametersMapping(Address address, ParametersMapping mapping) {
        String key = VARIABLE_PREFIX + "params.last." + address.toString();
        String json = gson.toJson(mapping);
        properties.setString(key, json);
    }
    
    /**
     * Get last parameters mapping for an address.
     */
    public ParametersMapping getLastParametersMapping(Address address) {
        String key = VARIABLE_PREFIX + "params.last." + address.toString();
        String json = properties.getString(key);
        if (json == null || json.isEmpty()) {
            return null;
        }
        return gson.fromJson(json, ParametersMapping.class);
    }

    /**
     * Store resolved variable storage identity for a function variable mapping key.
     */
    public void storeVariableIdentity(Address functionAddress, String variableKey, VariableStorageIdentity identity) {
        if (functionAddress == null || variableKey == null || variableKey.isBlank() || identity == null) {
            return;
        }
        Map<String, VariableStorageIdentity> identities = getVariableIdentities(functionAddress);
        identities.put(variableKey, identity);
        saveVariableIdentities(functionAddress, identities);
    }

    /**
     * Get known variable storage identities for a function.
     */
    public Map<String, VariableStorageIdentity> getVariableIdentities(Address functionAddress) {
        if (functionAddress == null) {
            return new HashMap<>();
        }
        String json = properties.getString(VARIABLE_IDENTITIES_PREFIX + functionAddress.toString());
        if (json == null || json.isEmpty()) {
            return new HashMap<>();
        }
        Type mapType = new TypeToken<Map<String, VariableStorageIdentity>>() { }.getType();
        Map<String, VariableStorageIdentity> identities = gson.fromJson(json, mapType);
        return identities != null ? identities : new HashMap<>();
    }

    /**
     * Store a content fingerprint of the last-applied struct definition.
     * Used to skip re-applying structs whose layout has not changed.
     */
    public void storeStructAppliedFingerprint(UUID structId, String fingerprint) {
        if (structId == null || fingerprint == null) {
            return;
        }
        properties.setString(STRUCT_PREFIX + "fingerprint." + structId.toString(), fingerprint);
    }

    /**
     * Get the stored fingerprint of the last-applied struct definition.
     */
    public String getStructAppliedFingerprint(UUID structId) {
        if (structId == null) {
            return null;
        }
        return properties.getString(STRUCT_PREFIX + "fingerprint." + structId.toString());
    }

    /**
     * Store mapping from struct UUID to data type path.
     */
    public void storeStructDataTypePath(UUID structId, String dataTypePath) {
        if (structId == null || dataTypePath == null || dataTypePath.isEmpty()) {
            return;
        }
        properties.setString(STRUCT_PREFIX + "path." + structId.toString(), dataTypePath);
    }

    /**
     * Resolve data type path by struct UUID.
     */
    public String getStructDataTypePath(UUID structId) {
        if (structId == null) {
            return null;
        }
        return properties.getString(STRUCT_PREFIX + "path." + structId.toString());
    }

    /**
     * Store canonical struct name by struct UUID.
     */
    public void storeStructName(UUID structId, String structName) {
        if (structId == null || structName == null || structName.isEmpty()) {
            return;
        }
        properties.setString(STRUCT_PREFIX + "name." + structId.toString(), structName);
    }

    /**
     * Resolve canonical struct name by struct UUID.
     */
    public String getStructName(UUID structId) {
        if (structId == null) {
            return null;
        }
        return properties.getString(STRUCT_PREFIX + "name." + structId.toString());
    }

    /**
     * Persist latest seen StructDefinition by struct id.
     */
    public void storeStructDefinition(StructDefinition definition) {
        if (definition == null || definition.getId() == null) {
            return;
        }
        Map<UUID, StructDefinition> registry = getStructRegistryDefinitions();
        registry.put(definition.getId(), definition);
        saveStructRegistryDefinitions(registry);
    }

    /**
     * Return all known StructDefinition entries keyed by struct UUID.
     */
    public Map<UUID, StructDefinition> getStructRegistryDefinitions() {
        String json = properties.getString(STRUCT_REGISTRY_KEY);
        if (json == null || json.isEmpty()) {
            return new HashMap<>();
        }
        Type mapType = new TypeToken<Map<String, StructDefinition>>() { }.getType();
        Map<String, StructDefinition> rawMap = gson.fromJson(json, mapType);
        Map<UUID, StructDefinition> byId = new HashMap<>();
        if (rawMap == null) {
            return byId;
        }
        for (Map.Entry<String, StructDefinition> entry : rawMap.entrySet()) {
            try {
                byId.put(UUID.fromString(entry.getKey()), entry.getValue());
            } catch (IllegalArgumentException ignored) {
                // Ignore invalid persisted UUID keys.
            }
        }
        return byId;
    }

    /**
     * Store collision-safe effective name for a struct id.
     */
    public void storeStructEffectiveName(UUID structId, String effectiveName) {
        if (structId == null || effectiveName == null || effectiveName.isBlank()) {
            return;
        }
        Map<String, String> names = getStructEffectiveNamesInternal();
        names.put(structId.toString(), effectiveName);
        properties.setString(STRUCT_EFFECTIVE_NAMES_KEY, gson.toJson(names));
    }

    /**
     * Lookup effective name for a struct id.
     */
    public String getStructEffectiveName(UUID structId) {
        if (structId == null) {
            return null;
        }
        return getStructEffectiveNamesInternal().get(structId.toString());
    }

    /**
     * Remove a set of child struct UUIDs from all {@code merged_from} lists
     * in the struct registry. Call this after successfully replacing/pruning
     * merged-from structs to prevent the cleaner from re-processing them on
     * every subsequent cycle.
     */
    public void scrubMergedFromReferences(java.util.Set<java.util.UUID> removedIds) {
        if (removedIds == null || removedIds.isEmpty()) {
            return;
        }
        Map<UUID, StructDefinition> registry = getStructRegistryDefinitions();
        boolean changed = false;
        for (StructDefinition def : registry.values()) {
            java.util.List<java.util.UUID> mf = def.getMergedFrom();
            if (mf != null && mf.removeAll(removedIds)) {
                changed = true;
            }
        }
        if (changed) {
            saveStructRegistryDefinitions(registry);
        }
    }

    /**
     * Remove all stored metadata for a struct UUID: registry entry, name, path,
     * effective name, fingerprint, and the global inference record.
     */
    public void removeStructMetadata(java.util.UUID structId) {
        if (structId == null) {
            return;
        }
        String idStr = structId.toString();

        Map<UUID, StructDefinition> registry = getStructRegistryDefinitions();
        if (registry.remove(structId) != null) {
            saveStructRegistryDefinitions(registry);
        }

        Map<String, String> effectiveNames = getStructEffectiveNamesInternal();
        if (effectiveNames.remove(idStr) != null) {
            properties.setString(STRUCT_EFFECTIVE_NAMES_KEY, gson.toJson(effectiveNames));
        }

        properties.removeOption(STRUCT_PREFIX + "name." + idStr);
        properties.removeOption(STRUCT_PREFIX + "path." + idStr);
        properties.removeOption(STRUCT_PREFIX + "fingerprint." + idStr);
        properties.removeOption(INFERENCE_PREFIX + "global." + idStr + ".struct_definition");
    }

    /**
     * Add or replace a deferred parameter type inference.
     */
    public void enqueueDeferredParameterType(ParameterType inference, int attempts) {
        if (inference == null || inference.getAddress() == null) {
            return;
        }
        String id = buildDeferredParameterInferenceId(inference);
        DeferredTypeInferenceRecord record = new DeferredTypeInferenceRecord(
            id,
            "parameter_type",
            attempts,
            inference,
            null
        );
        upsertDeferredTypeInference(record);
    }

    /**
     * Add or replace a deferred return type inference.
     */
    public void enqueueDeferredReturnType(ReturnType inference, int attempts) {
        if (inference == null || inference.getAddress() == null) {
            return;
        }
        String id = buildDeferredReturnInferenceId(inference);
        DeferredTypeInferenceRecord record = new DeferredTypeInferenceRecord(
            id,
            "return_type",
            attempts,
            null,
            inference
        );
        upsertDeferredTypeInference(record);
    }

    /**
     * Return all deferred parameter/return type inferences.
     */
    public List<DeferredTypeInferenceRecord> getDeferredTypeInferences() {
        Type mapType = new TypeToken<LinkedHashMap<String, DeferredTypeInferenceRecord>>() { }.getType();
        String json = properties.getString(DEFERRED_TYPE_INFERENCES_KEY);
        if (json == null || json.isEmpty()) {
            return java.util.Collections.emptyList();
        }
        LinkedHashMap<String, DeferredTypeInferenceRecord> byId = gson.fromJson(json, mapType);
        if (byId == null || byId.isEmpty()) {
            return java.util.Collections.emptyList();
        }
        return java.util.List.copyOf(byId.values());
    }

    /**
     * Remove deferred inference by id after successful apply.
     */
    public void removeDeferredTypeInference(String id) {
        if (id == null || id.isBlank()) {
            return;
        }
        Type mapType = new TypeToken<LinkedHashMap<String, DeferredTypeInferenceRecord>>() { }.getType();
        LinkedHashMap<String, DeferredTypeInferenceRecord> byId = readDeferredTypeInferencesMap(mapType);
        if (byId.remove(id) != null) {
            properties.setString(DEFERRED_TYPE_INFERENCES_KEY, gson.toJson(byId));
        }
    }

    /**
     * Mark parameter type as inferred so later updates can safely overwrite.
     */
    public void markInferredParameterType(Address address, int parameterIndex, String typeName) {
        if (address == null || parameterIndex < 0) {
            return;
        }
        String key = INFERRED_TYPE_PREFIX + "param." + address.toString() + "." + parameterIndex;
        properties.setString(key, typeName != null ? typeName : "inferred");
    }

    /**
     * Check whether a parameter type was inferred before.
     */
    public boolean wasParameterTypeInferred(Address address, int parameterIndex) {
        if (address == null || parameterIndex < 0) {
            return false;
        }
        String key = INFERRED_TYPE_PREFIX + "param." + address.toString() + "." + parameterIndex;
        String value = properties.getString(key);
        return value != null && !value.isEmpty();
    }

    /**
     * Mark return type as inferred so later updates can safely overwrite.
     */
    public void markInferredReturnType(Address address, String typeName) {
        if (address == null) {
            return;
        }
        String key = INFERRED_TYPE_PREFIX + "return." + address.toString();
        properties.setString(key, typeName != null ? typeName : "inferred");
    }

    /**
     * Check whether return type was inferred before.
     */
    public boolean wasReturnTypeInferred(Address address) {
        if (address == null) {
            return false;
        }
        String key = INFERRED_TYPE_PREFIX + "return." + address.toString();
        String value = properties.getString(key);
        return value != null && !value.isEmpty();
    }

    /**
     * Mark that the return type was successfully propagated to the returned local variable.
     */
    public void markReturnTypeLocalPropagated(Address address) {
        if (address == null) {
            return;
        }
        String key = INFERRED_TYPE_PREFIX + "return_local_propagated." + address.toString();
        properties.setString(key, "true");
    }

    /**
     * Check whether return type local propagation has been completed.
     */
    public boolean wasReturnTypeLocalPropagated(Address address) {
        if (address == null) {
            return false;
        }
        String key = INFERRED_TYPE_PREFIX + "return_local_propagated." + address.toString();
        String value = properties.getString(key);
        return "true".equals(value);
    }

    public String buildDeferredParameterInferenceId(ParameterType inference) {
        UUID structId = inference.getStructId();
        String structPart = structId != null ? structId.toString() : "none";
        return "parameter_type:" + inference.getAddress() + ":" + inference.getParameterIndex()
            + ":" + sanitizeForId(inference.getTypeAnnotation()) + ":" + structPart;
    }

    public String buildDeferredReturnInferenceId(ReturnType inference) {
        UUID structId = inference.getStructId();
        String structPart = structId != null ? structId.toString() : "none";
        return "return_type:" + inference.getAddress()
            + ":" + sanitizeForId(inference.getTypeAnnotation()) + ":" + structPart;
    }

    private void saveStructRegistryDefinitions(Map<UUID, StructDefinition> registry) {
        Map<String, StructDefinition> rawRegistry = new HashMap<>();
        for (Map.Entry<UUID, StructDefinition> entry : registry.entrySet()) {
            if (entry.getKey() != null && entry.getValue() != null) {
                rawRegistry.put(entry.getKey().toString(), entry.getValue());
            }
        }
        properties.setString(STRUCT_REGISTRY_KEY, gson.toJson(rawRegistry));
    }

    private Map<String, String> getStructEffectiveNamesInternal() {
        String json = properties.getString(STRUCT_EFFECTIVE_NAMES_KEY);
        if (json == null || json.isEmpty()) {
            return new HashMap<>();
        }
        Type mapType = new TypeToken<Map<String, String>>() { }.getType();
        Map<String, String> names = gson.fromJson(json, mapType);
        return names != null ? names : new HashMap<>();
    }

    private void saveVariableIdentities(Address functionAddress, Map<String, VariableStorageIdentity> identities) {
        if (functionAddress == null) {
            return;
        }
        properties.setString(VARIABLE_IDENTITIES_PREFIX + functionAddress.toString(), gson.toJson(identities));
    }

    private void upsertDeferredTypeInference(DeferredTypeInferenceRecord record) {
        if (record == null || record.getId() == null || record.getId().isBlank()) {
            return;
        }
        Type mapType = new TypeToken<LinkedHashMap<String, DeferredTypeInferenceRecord>>() { }.getType();
        LinkedHashMap<String, DeferredTypeInferenceRecord> byId = readDeferredTypeInferencesMap(mapType);
        byId.put(record.getId(), record);
        properties.setString(DEFERRED_TYPE_INFERENCES_KEY, gson.toJson(byId));
    }

    private LinkedHashMap<String, DeferredTypeInferenceRecord> readDeferredTypeInferencesMap(Type mapType) {
        String json = properties.getString(DEFERRED_TYPE_INFERENCES_KEY);
        if (json == null || json.isEmpty()) {
            return new LinkedHashMap<>();
        }
        LinkedHashMap<String, DeferredTypeInferenceRecord> map = gson.fromJson(json, mapType);
        return map != null ? map : new LinkedHashMap<>();
    }

    private String sanitizeForId(String value) {
        if (value == null || value.isBlank()) {
            return "none";
        }
        return value.replaceAll("\\s+", "_");
    }
}

