package com.zenyard.ghidra.util;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import com.zenyard.ghidra.api.AddressHelper;
import com.zenyard.ghidra.api.generated.model.ModelObject;
import com.zenyard.ghidra.api.generated.model.Section;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Group;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramFragment;
import ghidra.program.model.listing.ProgramModule;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;

/**
 * Utility for serializing program sections to API Section objects.
 *
 * <p>Sections are sourced from the program's default Program Tree fragments — for ELF, this
 * gives one entry per section header ({@code .text}, {@code .init}, {@code .fini}, …) even
 * when the loader merges them into a single LOAD memory block. Mirrors the granularity of
 * IDA's {@code idautils.Segments()}.</p>
 *
 * <p>Falls back to {@code Memory.getBlocks()} when no default tree exists (raw binaries,
 * formats without a tree-emitting loader).</p>
 */
public class SectionSerializer {

    /**
     * A logical section: a Program Tree fragment paired with its containing memory block,
     * or a memory block standing in for itself when no tree is available. The block supplies
     * permission/class metadata that fragments don't carry directly.
     */
    public record SectionView(Address start, String name, long size, MemoryBlock block) {}

    public static List<ModelObject> serializeAllSections(Program program) {
        List<ModelObject> objects = new ArrayList<>();
        for (SectionView view : enumerateSections(program)) {
            ModelObject obj = new ModelObject();
            obj.setActualInstance(serializeSection(view));
            objects.add(obj);
        }
        return objects;
    }

    /**
     * Find a section starting at {@code address}, if any. Used by per-address paths
     * (dirty-address dispatch, inference applier) to keep detection consistent with the
     * bulk enumeration in {@link #serializeAllSections}.
     */
    public static Optional<SectionView> findSectionAt(Program program, Address address) {
        if (address == null) {
            return Optional.empty();
        }
        for (SectionView view : enumerateSections(program)) {
            if (view.start().equals(address)) {
                return Optional.of(view);
            }
        }
        return Optional.empty();
    }

    /**
     * Enumerate sections via the default Program Tree, falling back to memory blocks.
     */
    public static List<SectionView> enumerateSections(Program program) {
        List<SectionView> result = new ArrayList<>();
        Memory memory = program.getMemory();
        ProgramModule root = program.getListing().getDefaultRootModule();
        if (root != null) {
            collectFragments(root, memory, result);
        }
        if (!result.isEmpty()) {
            return result;
        }
        for (MemoryBlock block : memory.getBlocks()) {
            long size = block.getEnd().subtract(block.getStart()) + 1;
            result.add(new SectionView(block.getStart(), block.getName(), size, block));
        }
        return result;
    }

    public static Section serializeSection(SectionView view) {
        Section section = new Section();
        section.setAddress(AddressHelper.fromAddress(view.start()));
        section.setName(view.name());
        section.setHasKnownName(true);
        section.setInferenceSeqNumber(0);
        section.setSize((int) view.size());

        MemoryBlock block = view.block();
        boolean read = block != null && block.isRead();
        boolean write = block != null && block.isWrite();
        boolean execute = block != null && block.isExecute();
        section.setRead(read);
        section.setWrite(write);
        section.setExecute(execute);
        section.setClass(execute ? Section.ClassEnum.CODE : Section.ClassEnum.DATA);
        return section;
    }

    private static void collectFragments(Group group, Memory memory, List<SectionView> out) {
        if (group instanceof ProgramFragment fragment) {
            if (shouldUploadFragment(fragment)) {
                Address start = fragment.getMinAddress();
                out.add(new SectionView(start, fragment.getName(),
                        fragment.getNumAddresses(), memory.getBlock(start)));
            }
            return;
        }
        if (group instanceof ProgramModule module) {
            for (Group child : module.getChildren()) {
                collectFragments(child, memory, out);
            }
        }
    }

    /**
     * A program-tree fragment is uploaded as a section iff it is non-empty and
     * its start address lives in a loaded-memory space. Fragments anchored in
     * non-loaded spaces (e.g. Ghidra's OTHER_SPACE for ELF section/program-header
     * metadata or debug info) don't correspond to addresses any code dereferences,
     * so they contribute nothing to the server's global-pattern range check, and
     * multiple such fragments collide on address 0x0 — breaking the
     * (binary_id, address, min_revision) primary key when uploaded together.
     */
    static boolean shouldUploadFragment(ProgramFragment fragment) {
        if (fragment == null || fragment.isEmpty()) {
            return false;
        }
        Address start = fragment.getMinAddress();
        return start != null && start.getAddressSpace().isLoadedMemorySpace();
    }
}
