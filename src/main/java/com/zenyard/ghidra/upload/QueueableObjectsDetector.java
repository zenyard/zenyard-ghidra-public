package com.zenyard.ghidra.upload;

import java.util.List;

import com.zenyard.ghidra.storage.SyncStatusStorage;
import com.zenyard.ghidra.storage.ZenyardProgramProperties;
import com.zenyard.ghidra.util.ObjectGraph.Symbol;
import com.zenyard.ghidra.util.ObjectReader;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;

/**
 * Determines whether the current program has queueable objects for revision upload.
 */
public final class QueueableObjectsDetector {

    private QueueableObjectsDetector() {
    }

    public static boolean hasQueueableObjects(Program program) {
        if (program == null || program.isClosed()) {
            return false;
        }

        SyncStatusStorage syncStatusStorage = new SyncStatusStorage(program);
        List<Address> dirtyAddresses = syncStatusStorage.getDirtyAddresses();
        if (!dirtyAddresses.isEmpty()) {
            for (Address dirtyAddress : dirtyAddresses) {
                if (ObjectReader.getObjectSymbolForAddress(program, dirtyAddress).isPresent()) {
                    return true;
                }
            }
            return false;
        }

        ZenyardProgramProperties props = new ZenyardProgramProperties(program);
        if (!"true".equals(props.getString("database_dirty"))) {
            return false;
        }

        for (Symbol symbol : ObjectReader.getAllObjectSymbols(program)) {
            if (syncStatusStorage.isDirty(symbol.getAddress())) {
                return true;
            }
        }
        return false;
    }
}
