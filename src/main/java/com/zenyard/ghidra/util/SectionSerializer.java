package com.zenyard.ghidra.util;

import java.util.ArrayList;
import java.util.List;

import com.zenyard.ghidra.api.AddressHelper;
import com.zenyard.ghidra.api.generated.model.ModelObject;
import com.zenyard.ghidra.api.generated.model.Section;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;

/**
 * Utility for serializing Ghidra memory blocks to API Section objects.
 */
public class SectionSerializer {

    /**
     * Serialize all memory blocks in the program to API Section objects
     * wrapped in ModelObject for upload.
     */
    public static List<ModelObject> serializeAllSections(Program program) {
        List<ModelObject> objects = new ArrayList<>();
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            Section section = serializeBlock(block);
            ModelObject obj = new ModelObject();
            obj.setActualInstance(section);
            objects.add(obj);
        }
        return objects;
    }

    /**
     * Serialize a single memory block to an API Section object.
     */
    public static Section serializeBlock(MemoryBlock block) {
        Section section = new Section();
        section.setAddress(AddressHelper.fromAddress(block.getStart()));
        section.setName(block.getName());
        section.setHasKnownName(true);
        section.setInferenceSeqNumber(0);
        long size = block.getEnd().subtract(block.getStart()) + 1;
        section.setSize((int) size);
        section.setClass(classifyBlock(block));
        section.setRead(block.isRead());
        section.setWrite(block.isWrite());
        section.setExecute(block.isExecute());
        return section;
    }

    private static Section.ClassEnum classifyBlock(MemoryBlock block) {
        if (block.isExecute()) {
            return Section.ClassEnum.CODE;
        }
        return Section.ClassEnum.DATA;
    }
}
