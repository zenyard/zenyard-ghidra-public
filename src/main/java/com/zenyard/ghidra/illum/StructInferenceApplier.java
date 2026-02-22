package com.zenyard.ghidra.illum;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.zenyard.ghidra.api.generated.model.FieldDefinition;
import com.zenyard.ghidra.api.generated.model.StructDefinition;
import com.zenyard.ghidra.storage.InferenceStorage;

import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DoubleDataType;
import ghidra.program.model.data.FloatDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.Undefined1DataType;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

/**
 * Applies struct reconstruction inferences to Ghidra data types.
 */
public class StructInferenceApplier {

    private static final CategoryPath STRUCT_CATEGORY = new CategoryPath("/zenyard/structs");
    private static final Pattern ARRAY_PATTERN = Pattern.compile(".*\\[(\\d+)\\]\\s*$");

    private final InferenceStorage inferenceStorage;

    public StructInferenceApplier(InferenceStorage inferenceStorage) {
        this.inferenceStorage = inferenceStorage;
    }

    /**
     * Create/update structure type based on struct_definition inference.
     */
    public void applyStructDefinition(Program program, StructDefinition definition) {
        applyStructDefinition(program, definition, null);
    }

    /**
     * Create/update structure type with an optional externally resolved effective name.
     */
    public void applyStructDefinition(Program program, StructDefinition definition, String effectiveName) {
        applyStructDefinition(program, definition, effectiveName, null);
    }

    /**
     * Create/update structure type with an optional externally resolved effective name.
     * When cycleMembers is non-null and contains definition.getId(), ensures self-referential
     * structs (e.g. linked-list Node) have enough space for a pointer field at offset 8,
     * fixing "Field next does not fit in structure Node" decompilation errors.
     */
    public void applyStructDefinition(Program program, StructDefinition definition, String effectiveName,
            Set<UUID> cycleMembers) {
        if (program == null || definition == null || definition.getId() == null) {
            return;
        }

        DataTypeManager dtm = program.getDataTypeManager();
        String structName = sanitizeName(
            effectiveName != null && !effectiveName.isBlank() ? effectiveName : definition.getName(),
            "inferred_struct"
        );

        // Detect name collision: if a struct with this name already exists but was
        // created by a different struct ID, disambiguate by appending the first 8
        // hex characters of this definition's UUID.
        structName = disambiguateStructName(dtm, structName, definition.getId());

        List<FieldDefinition> fields = new ArrayList<>(
            definition.getFieldDefinitions() != null ? definition.getFieldDefinitions() : List.of()
        );
        fields.sort(Comparator.comparingInt(f -> f.getFieldOffset() != null ? f.getFieldOffset().intValue() : 0));

        boolean isCycleMember = cycleMembers != null && cycleMembers.contains(definition.getId());
        String fingerprint = computeStructFingerprint(structName, fields, isCycleMember);
        String lastFingerprint = inferenceStorage.getStructAppliedFingerprint(definition.getId());
        if (fingerprint.equals(lastFingerprint)) {
            Msg.info(this, "Skipping unchanged struct '" + structName + "' id=" + definition.getId());
            return;
        }

        Structure structure = ensureStructure(dtm, structName);
        structure.deleteAll();

        for (FieldDefinition field : fields) {
            if (field == null) {
                continue;
            }
            Integer offsetObj = field.getFieldOffset();
            int offset = offsetObj != null ? offsetObj.intValue() : 0;
            if (offset < 0) {
                continue;
            }

            String fieldName = sanitizeName(field.getSuggestedFieldName(), "field_" + offset);
            DataType fieldType = resolveInferenceDataType(program, field.getFieldType(), field.getStructId());
            if (fieldType == null) {
                fieldType = resolveFallbackFieldType(program, definition, structure, structName, field);
                if (fieldType == null) {
                    Msg.warn(this, "Failed resolving struct field type for " + structName + "." + fieldName
                        + " annotation=" + field.getFieldType());
                    fieldType = Undefined1DataType.dataType;
                }
            }

            int fieldLength = Math.max(1, getSafeDataTypeLength(fieldType, program));
            ensureStructureLength(structure, offset + fieldLength);
            try {
                DataTypeComponent existing = structure.getComponentAt(offset);
                if (existing != null && !(existing.getDataType() instanceof Undefined1DataType)) {
                    structure.delete(existing.getOrdinal());
                }
                ensureStructureLength(structure, offset + fieldLength);
                structure.insertAtOffset(offset, fieldType, fieldLength, fieldName, null);
            } catch (Exception e) {
                Msg.warn(this, "Failed applying field " + fieldName + " at +" + offset + ": " + e.getMessage());
            }
        }

        ensureCycleStructPointerField(program, definition, structure, structName, cycleMembers);

        DataType resolved = dtm.resolve(structure, DataTypeConflictHandler.REPLACE_HANDLER);
        inferenceStorage.storeStructDataTypePath(definition.getId(), resolved.getPathName());
        inferenceStorage.storeStructName(definition.getId(), structName);
        inferenceStorage.storeStructEffectiveName(definition.getId(), structName);
        inferenceStorage.storeStructDefinition(definition);
        inferenceStorage.storeStructAppliedFingerprint(definition.getId(), fingerprint);

        int fieldCount = fields.size();
        int resolvedLength = resolved instanceof Structure ? ((Structure) resolved).getLength() : -1;
        Msg.info(this, "Applied struct_definition '" + structName + "' id=" + definition.getId()
            + " fields=" + fieldCount + " size=" + resolvedLength
            + " cycle=" + (cycleMembers != null && cycleMembers.contains(definition.getId())));
    }

    /**
     * Return direct struct dependencies referenced by field struct_id.
     */
    public Set<UUID> extractStructDependencies(StructDefinition definition) {
        Set<UUID> dependencies = new HashSet<>();
        if (definition == null || definition.getFieldDefinitions() == null) {
            return dependencies;
        }
        for (FieldDefinition field : definition.getFieldDefinitions()) {
            if (field != null && field.getStructId() != null) {
                dependencies.add(field.getStructId());
            }
        }
        return dependencies;
    }

    /**
     * Resolve type annotation to data type, optionally preferring struct_id mapping.
     */
    public DataType resolveInferenceDataType(Program program, String typeAnnotation, UUID structId) {
        if (program == null) {
            return null;
        }
        DataTypeManager dtm = program.getDataTypeManager();

        if (structId != null) {
            DataType mappedStruct = resolveStructTypeById(program, structId);
            if (mappedStruct != null) {
                return applyPointerDepth(mappedStruct, countTrailingPointers(typeAnnotation));
            }
            // When a struct_id is provided, require an actual mapped struct to avoid
            // falsely resolving to an unrelated named type (e.g. typedef/placeholder).
            return null;
        }

        if (typeAnnotation == null || typeAnnotation.trim().isEmpty()) {
            return null;
        }

        int pointerDepth = countTrailingPointers(typeAnnotation);
        String normalized = normalizeTypeName(typeAnnotation);
        int arrayCount = parseArrayCount(normalized);
        String baseTypeName = stripArraySuffix(normalized);

        DataType baseType = resolveBaseType(dtm, baseTypeName);
        if (baseType == null && baseTypeName.startsWith("struct ")) {
            baseType = resolveBaseType(dtm, baseTypeName.substring("struct ".length()).trim());
        }
        if (baseType == null) {
            return null;
        }

        DataType resolved = baseType;
        if (arrayCount > 0 && pointerDepth == 0) {
            int elementLength = Math.max(1, getSafeDataTypeLength(baseType, program));
            resolved = new ArrayDataType(baseType, arrayCount, elementLength, dtm);
        }
        return applyPointerDepth(resolved, pointerDepth);
    }

    /**
     * Lookup previously created struct type by struct UUID.
     */
    public DataType resolveStructTypeById(Program program, UUID structId) {
        if (program == null || structId == null) {
            return null;
        }
        DataTypeManager dtm = program.getDataTypeManager();

        String mappedPath = inferenceStorage.getStructDataTypePath(structId);
        if (mappedPath != null && !mappedPath.isEmpty()) {
            DataType byPath = dtm.getDataType(mappedPath);
            if (byPath != null) {
                return byPath;
            }
        }

        String mappedName = inferenceStorage.getStructName(structId);
        if (mappedName != null && !mappedName.isEmpty()) {
            return dtm.getDataType(STRUCT_CATEGORY, mappedName);
        }

        return null;
    }

    /**
     * Resolve fallback type when primary resolution fails.
     * For pointer-like fields: use PointerDataType to the same struct if self-referential,
     * otherwise use generic PointerDataType (void*).
     */
    private DataType resolveFallbackFieldType(
            Program program,
            StructDefinition definition,
            Structure structure,
            String structName,
            FieldDefinition field) {
        if (program == null || definition == null || structure == null || field == null) {
            return null;
        }
        String typeAnnotation = field.getFieldType();
        int pointerDepth = countTrailingPointers(typeAnnotation);
        if (pointerDepth <= 0) {
            return null;
        }
        boolean isSelfReferential = definition.getId() != null
            && definition.getId().equals(field.getStructId());
        if (!isSelfReferential && typeAnnotation != null) {
            String baseTypeName = stripArraySuffix(normalizeTypeName(typeAnnotation));
            if (baseTypeName.startsWith("struct ")) {
                baseTypeName = baseTypeName.substring(7).trim();
            }
            String defName = definition.getName() != null ? definition.getName() : "";
            isSelfReferential = baseTypeName.equalsIgnoreCase(defName)
                || baseTypeName.equalsIgnoreCase(structName)
                || sanitizeName(baseTypeName, "").equals(sanitizeName(structName, ""));
        }
        if (isSelfReferential) {
            DataType ptrToSelf = new PointerDataType(structure);
            return pointerDepth > 1 ? applyPointerDepth(ptrToSelf, pointerDepth - 1) : ptrToSelf;
        }
        return new PointerDataType();
    }

    /**
     * If a struct with the given name already exists in the zenyard category but belongs
     * to a different struct ID, append the first 8 hex characters of this definition's
     * UUID to avoid overwriting the other struct's definition.
     */
    private String disambiguateStructName(DataTypeManager dtm, String baseName, UUID structId) {
        DataType existing = dtm.getDataType(STRUCT_CATEGORY, baseName);
        if (existing == null) {
            return baseName;
        }
        // Check if this struct ID already owns this name (update, not collision)
        String storedName = inferenceStorage.getStructName(structId);
        if (baseName.equals(storedName)) {
            return baseName;
        }

        // Collision: another struct already uses this name.
        // If the existing owner is an inferred struct, rename it too so both colliding
        // structs get deterministic "<name>_<first8charsOfId>" naming.
        UUID existingOwnerId = findStructOwnerIdByName(baseName, structId);
        if (existingOwnerId != null) {
            String existingDisambiguated = withStructIdSuffix(baseName, existingOwnerId);
            renameExistingStructForCollision(dtm, baseName, existingDisambiguated, existingOwnerId);
        }

        String disambiguated = withStructIdSuffix(baseName, structId);
        Msg.info(this, "Struct name collision for '" + baseName
            + "': using disambiguated name '" + disambiguated + "' for id=" + structId);
        return disambiguated;
    }

    private String withStructIdSuffix(String baseName, UUID structId) {
        if (baseName == null || structId == null) {
            return baseName;
        }
        String idHex = structId.toString().replace("-", "");
        String suffix = idHex.substring(0, Math.min(8, idHex.length()));
        return baseName + "_" + suffix;
    }

    private UUID findStructOwnerIdByName(String structName, UUID exceptId) {
        if (structName == null || structName.isBlank()) {
            return null;
        }
        for (UUID candidateId : inferenceStorage.getStructRegistryDefinitions().keySet()) {
            if (candidateId == null || candidateId.equals(exceptId)) {
                continue;
            }
            String effectiveName = inferenceStorage.getStructEffectiveName(candidateId);
            if (structName.equals(effectiveName)) {
                return candidateId;
            }
            String canonicalName = inferenceStorage.getStructName(candidateId);
            if (structName.equals(canonicalName)) {
                return candidateId;
            }
        }
        return null;
    }

    private void renameExistingStructForCollision(DataTypeManager dtm, String oldName, String newName,
            UUID ownerId) {
        if (oldName == null || newName == null || oldName.equals(newName)) {
            return;
        }
        DataType existing = dtm.getDataType(STRUCT_CATEGORY, oldName);
        if (!(existing instanceof Structure)) {
            return;
        }
        if (dtm.getDataType(STRUCT_CATEGORY, newName) != null) {
            return;
        }
        try {
            ((Structure) existing).setName(newName);
            DataType renamed = dtm.getDataType(STRUCT_CATEGORY, newName);
            inferenceStorage.storeStructName(ownerId, newName);
            inferenceStorage.storeStructEffectiveName(ownerId, newName);
            if (renamed != null) {
                inferenceStorage.storeStructDataTypePath(ownerId, renamed.getPathName());
            }
            Msg.info(this, "Renamed colliding existing struct '" + oldName + "' -> '" + newName
                + "' for id=" + ownerId);
        } catch (Exception e) {
            Msg.warn(this, "Failed renaming colliding existing struct '" + oldName + "' -> '"
                + newName + "': " + e.getMessage());
        }
    }

    private Structure ensureStructure(DataTypeManager dtm, String structName) {
        DataType existing = dtm.getDataType(STRUCT_CATEGORY, structName);
        if (existing instanceof Structure) {
            return (Structure) existing;
        }

        StructureDataType candidate = new StructureDataType(STRUCT_CATEGORY, structName, 0, dtm);
        DataType resolved = dtm.resolve(candidate, DataTypeConflictHandler.REPLACE_HANDLER);
        if (resolved instanceof Structure) {
            return (Structure) resolved;
        }
        return candidate;
    }

    private DataType resolveBaseType(DataTypeManager dtm, String typeName) {
        if (typeName == null || typeName.isEmpty()) {
            return null;
        }

        DataType exactPath = dtm.getDataType("/" + typeName);
        if (exactPath != null) {
            return exactPath;
        }

        DataType structScoped = dtm.getDataType(STRUCT_CATEGORY, sanitizeName(typeName, typeName));
        if (structScoped != null) {
            return structScoped;
        }

        String lower = typeName.toLowerCase();
        switch (lower) {
            case "void":
                return dtm.getDataType("/void");
            case "char":
            case "int8_t":
                return firstNonNull(dtm.getDataType("/char"), dtm.getDataType("/byte"));
            case "unsigned char":
            case "uint8_t":
                return firstNonNull(dtm.getDataType("/uchar"), dtm.getDataType("/byte"));
            case "short":
            case "int16_t":
                return dtm.getDataType("/short");
            case "unsigned short":
            case "uint16_t":
                return dtm.getDataType("/ushort");
            case "int":
            case "int32_t":
                return dtm.getDataType("/int");
            case "unsigned":
            case "unsigned int":
            case "uint":
            case "uint32_t":
                return firstNonNull(dtm.getDataType("/uint"), dtm.getDataType("/dword"));
            case "long":
            case "long int":
            case "int64_t":
                return firstNonNull(dtm.getDataType("/longlong"), dtm.getDataType("/long"));
            case "unsigned long":
            case "unsigned long int":
            case "uint64_t":
                return firstNonNull(dtm.getDataType("/ulonglong"), dtm.getDataType("/ulong"));
            case "float":
            case "float_t":
            case "float32":
            case "float32_t":
            case "f32":
            case "real4":
                return firstNonNull(dtm.getDataType("/float"), FloatDataType.dataType);
            case "double":
            case "double_t":
            case "float64":
            case "float64_t":
            case "f64":
            case "real8":
                return firstNonNull(dtm.getDataType("/double"), DoubleDataType.dataType);
            case "bool":
            case "_bool":
                return firstNonNull(dtm.getDataType("/bool"), dtm.getDataType("/byte"));
            default:
                return null;
        }
    }

    private void ensureStructureLength(Structure structure, int requiredLength) {
        int currentLength = structure.getLength();
        if (requiredLength > currentLength) {
            structure.growStructure(requiredLength - currentLength);
        }
    }

    /**
     * For structs in a cycle (e.g. linked-list Node) or structs with self-referential pointer
     * fields detected by name, ensure there is space for the pointer field when the inference
     * omits it or uses a wrong-sized type. Fixes "Field X does not fit in structure Y"
     * decompilation errors.
     *
     * This method runs in two modes:
     * <ol>
     *   <li>Cycle-member mode: struct is in cycleMembers set (detected via topological sort)</li>
     *   <li>Name-match mode: a field in the definition has a pointer type referencing the struct
     *       by name (e.g. "struct LinkedListNode*" in struct LinkedListNode). This covers
     *       cases where struct_id was lost after Gson round-trip.</li>
     * </ol>
     */
    private void ensureCycleStructPointerField(Program program, StructDefinition definition,
            Structure structure, String structName, Set<UUID> cycleMembers) {
        if (program == null || definition == null || structure == null) {
            return;
        }

        boolean isCycleMember = cycleMembers != null && cycleMembers.contains(definition.getId());

        int pointerSize = program.getDefaultPointerSize();
        if (pointerSize < 4) {
            return;
        }

        List<FieldDefinition> fields = definition.getFieldDefinitions();
        if (fields == null || fields.isEmpty()) {
            return;
        }

        for (FieldDefinition field : fields) {
            if (field == null) {
                continue;
            }
            String fieldAnnotation = field.getFieldType();
            int pointerDepth = countTrailingPointers(fieldAnnotation);
            if (pointerDepth <= 0) {
                continue;
            }
            boolean isSelfRef = isCycleMember;
            if (!isSelfRef) {
                isSelfRef = definition.getId() != null
                    && definition.getId().equals(field.getStructId());
            }
            if (!isSelfRef && fieldAnnotation != null) {
                String baseTypeName = stripArraySuffix(normalizeTypeName(fieldAnnotation));
                if (baseTypeName.startsWith("struct ")) {
                    baseTypeName = baseTypeName.substring(7).trim();
                }
                String defName = definition.getName() != null ? definition.getName() : "";
                isSelfRef = baseTypeName.equalsIgnoreCase(defName)
                    || baseTypeName.equalsIgnoreCase(structName)
                    || sanitizeName(baseTypeName, "").equals(sanitizeName(structName, ""));
            }
            if (!isSelfRef) {
                continue;
            }

            Integer offsetObj = field.getFieldOffset();
            int pointerOffset = offsetObj != null ? offsetObj.intValue() : -1;
            if (pointerOffset < 0) {
                continue;
            }

            DataTypeComponent atOffset = structure.getComponentAt(pointerOffset);
            boolean needsPointer = false;
            if (atOffset == null) {
                needsPointer = structure.getLength() < pointerOffset + pointerSize;
            } else if (atOffset.getLength() < pointerSize) {
                try {
                    structure.delete(atOffset.getOrdinal());
                    needsPointer = true;
                } catch (Exception e) {
                    Msg.warn(this, "Failed removing undersized field at +" + pointerOffset + " in " + structName
                            + ": " + e.getMessage());
                    continue;
                }
            }
            if (!needsPointer) {
                continue;
            }
            String fieldName = sanitizeName(field.getSuggestedFieldName(), "self_ptr_" + pointerOffset);
            DataType ptrToSelf = new PointerDataType(structure);
            ensureStructureLength(structure, pointerOffset + pointerSize);
            try {
                structure.insertAtOffset(pointerOffset, ptrToSelf, pointerSize, fieldName, null);
                Msg.info(this, "Added self-referential '" + fieldName + "' at +" + pointerOffset
                        + " for struct " + structName + " (cycle=" + isCycleMember + ")");
            } catch (Exception e) {
                Msg.warn(this, "Failed adding self-referential pointer field for " + structName + " at +"
                        + pointerOffset + ": " + e.getMessage());
            }
        }
    }

    /**
     * Compute a deterministic fingerprint of a struct definition layout.
     * Used to detect whether a struct has changed since it was last applied,
     * avoiding unnecessary DTM modifications that trigger auto-analysis and
     * overwrite previously applied variable renames.
     */
    private String computeStructFingerprint(String effectiveName, List<FieldDefinition> fields,
            boolean isCycleMember) {
        StringBuilder sb = new StringBuilder();
        sb.append("name=").append(effectiveName != null ? effectiveName : "");
        sb.append("|cycle=").append(isCycleMember);
        for (FieldDefinition field : fields) {
            if (field == null) {
                continue;
            }
            sb.append("|");
            sb.append(field.getFieldOffset() != null ? field.getFieldOffset() : "?");
            sb.append(":");
            sb.append(field.getSuggestedFieldName() != null ? field.getSuggestedFieldName() : "");
            sb.append(":");
            sb.append(field.getFieldType() != null ? field.getFieldType() : "");
            sb.append(":");
            sb.append(field.getStructId() != null ? field.getStructId() : "");
        }
        return sb.toString();
    }

    private int getSafeDataTypeLength(DataType dataType, Program program) {
        int length = dataType != null ? dataType.getLength() : 0;
        if (length > 0) {
            return length;
        }
        return Math.max(1, program.getDefaultPointerSize());
    }

    private DataType applyPointerDepth(DataType base, int pointerDepth) {
        DataType result = base;
        for (int i = 0; i < pointerDepth; i++) {
            result = new PointerDataType(result);
        }
        return result;
    }

    private int parseArrayCount(String normalized) {
        if (normalized == null) {
            return -1;
        }
        Matcher matcher = ARRAY_PATTERN.matcher(normalized);
        if (!matcher.matches()) {
            return -1;
        }
        try {
            return Integer.parseInt(matcher.group(1));
        } catch (NumberFormatException e) {
            return -1;
        }
    }

    private String stripArraySuffix(String normalized) {
        if (normalized == null) {
            return "";
        }
        return normalized.replaceAll("\\s*\\[\\d+\\]\\s*$", "").trim();
    }

    private int countTrailingPointers(String typeAnnotation) {
        if (typeAnnotation == null) {
            return 0;
        }
        int count = 0;
        for (int i = typeAnnotation.length() - 1; i >= 0; i--) {
            char c = typeAnnotation.charAt(i);
            if (c == '*') {
                count++;
            } else if (!Character.isWhitespace(c)) {
                break;
            }
        }
        return count;
    }

    private String normalizeTypeName(String typeAnnotation) {
        String normalized = typeAnnotation != null ? typeAnnotation.trim() : "";
        normalized = normalized.replaceAll("\\bconst\\b", "")
            .replaceAll("\\bvolatile\\b", "")
            .replaceAll("\\brestrict\\b", "")
            .trim();
        while (normalized.endsWith("*")) {
            normalized = normalized.substring(0, normalized.length() - 1).trim();
        }
        return normalized;
    }

    private DataType firstNonNull(DataType first, DataType second) {
        return first != null ? first : second;
    }

    private String sanitizeName(String value, String fallback) {
        String candidate = value == null ? "" : value.trim();
        if (candidate.isEmpty()) {
            candidate = fallback;
        }
        candidate = candidate.replaceAll("[^A-Za-z0-9_]", "_");
        if (!candidate.isEmpty() && Character.isDigit(candidate.charAt(0))) {
            candidate = "_" + candidate;
        }
        return candidate;
    }
}
