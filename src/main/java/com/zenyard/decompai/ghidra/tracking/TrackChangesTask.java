package com.zenyard.decompai.ghidra.tracking;

import ghidra.framework.data.DomainObjectAdapterDB;
import ghidra.framework.model.DomainObjectListener;
import ghidra.framework.model.DomainObjectListenerBuilder;
import ghidra.framework.model.TransactionInfo;
import ghidra.framework.model.TransactionListener;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.util.CodeUnitPropertyChangeRecord;
import ghidra.program.util.ProgramChangeRecord;
import ghidra.program.util.ProgramEvent;
import com.zenyard.decompai.ghidra.events.DecompaiEvent;
import com.zenyard.decompai.ghidra.events.EventDispatcher;
import com.zenyard.decompai.ghidra.events.EventProducer;
import com.zenyard.decompai.ghidra.storage.DecompaiProgramProperties;
import com.zenyard.decompai.ghidra.storage.SyncStatusStorage;
import ghidra.util.Msg;

import java.util.EnumSet;
import java.util.HashSet;
import java.util.Set;

import static ghidra.program.util.ProgramEvent.*;

/**
 * Event-driven change tracker that listens to program changes and marks objects as dirty.
 * Publishes CHANGES_DETECTED events when changes are detected.
 * 
 * Tracks "Edit Label" and "Rename Local Variable" task completion via TransactionListener 
 * instead of symbol events. When these transactions complete, marks affected addresses as dirty.
 */
public class TrackChangesTask implements EventProducer {
    
    private static final String EDIT_LABEL_TRANSACTION = "Edit Label";
    private static final String RENAME_LOCAL_VARIABLE_TRANSACTION = "Rename Local Variable";
    private static final Set<ProgramEvent> PROPAGATE_NON_OBJECT_EVENTS = EnumSet.of(
        FUNCTION_ADDED,
        FUNCTION_REMOVED,
        FUNCTION_BODY_CHANGED,
        FUNCTION_CHANGED,
        SYMBOL_ADDED,
        SYMBOL_RENAMED,
        SYMBOL_REMOVED,
        CODE_ADDED,
        CODE_REMOVED,
        CODE_REPLACED,
        REFERENCE_ADDED,
        REFERENCE_REMOVED,
        REFERENCE_TYPE_CHANGED,
        VARIABLE_REFERENCE_ADDED,
        VARIABLE_REFERENCE_REMOVED
    );
    private static final Set<ProgramEvent> IGNORE_IN_MID_OBJECT = EnumSet.of(
        COMMENT_CHANGED
    );
    private static final String PROPERTY_PREFIX = "DecompAI.";
    
    private final SyncStatusStorage syncStatusStorage;
    private final Program program;
    private final EventDispatcher eventDispatcher;
    private DomainObjectListener symbolListener; // Only used to track addresses during "Edit Label" and "Rename Local Variable" transactions
    private TransactionListener transactionListener;
    private volatile boolean ignoreEvents = true;
    private volatile boolean trackingEditLabelTransaction = false;
    private final Set<Address> editLabelAffectedAddresses = new HashSet<>();
    
    public TrackChangesTask(Program program, SyncStatusStorage syncStatusStorage, EventDispatcher eventDispatcher) {
        this.program = program;
        this.syncStatusStorage = syncStatusStorage;
        this.eventDispatcher = eventDispatcher;
        this.symbolListener = createSymbolListener(); // Only tracks during "Edit Label" and "Rename Local Variable" transactions
        this.transactionListener = createTransactionListener();

        Msg.info(this, "TrackChangesTask initialized: ignoreEvents=" + this.ignoreEvents);
    }
    
    @Override
    public void publishEvent(DecompaiEvent event) {
        if (eventDispatcher != null) {
            eventDispatcher.publish(event);
        }
    }
    
    /**
     * Create the domain object listener for tracking symbol changes.
     * This listener is ONLY used to collect affected addresses during "Edit Label" and 
     * "Rename Local Variable" transactions. It does not mark objects as dirty directly - 
     * that happens when the transaction completes.
     */
    private DomainObjectListener createSymbolListener() {
        return new DomainObjectListenerBuilder(this)
            .with(ProgramChangeRecord.class)
                .each(SYMBOL_ADDED, SYMBOL_RENAMED, SYMBOL_REMOVED)
                    .call(this::handleSymbolEvent)
                .each(CODE_ADDED, CODE_REMOVED, CODE_REPLACED, COMMENT_CHANGED, REFERENCE_ADDED,
                    REFERENCE_REMOVED, REFERENCE_TYPE_CHANGED, VARIABLE_REFERENCE_ADDED,
                    VARIABLE_REFERENCE_REMOVED, FUNCTION_ADDED, FUNCTION_REMOVED,
                    FUNCTION_BODY_CHANGED, FUNCTION_CHANGED)
                    .call(this::handleProgramChange)
            .build();
    }
    
    /**
     * Create the transaction listener for tracking "Edit Label" and "Rename Local Variable" task completion.
     */
    private TransactionListener createTransactionListener() {
        return new TransactionListener() {
            @Override
            public void transactionStarted(DomainObjectAdapterDB domainObj, TransactionInfo tx) {
                if (ignoreEvents) {
                    return;
                }
                String description = tx.getDescription();
                if (EDIT_LABEL_TRANSACTION.equals(description) || 
                    RENAME_LOCAL_VARIABLE_TRANSACTION.equals(description)) {
                    synchronized (editLabelAffectedAddresses) {
                        trackingEditLabelTransaction = true;
                        editLabelAffectedAddresses.clear();
                    }
                    Msg.info(TrackChangesTask.this, "TrackChangesTask: " + description + " transaction started");
                }
            }
            
            @Override
            public void transactionEnded(DomainObjectAdapterDB domainObj) {
                if (ignoreEvents) {
                    return;
                }
                synchronized (editLabelAffectedAddresses) {
                    if (trackingEditLabelTransaction) {
                        trackingEditLabelTransaction = false;
                        Msg.info(TrackChangesTask.this, "TrackChangesTask: Edit Label transaction ended, marking " + 
                            editLabelAffectedAddresses.size() + " addresses as dirty");
                        
                        // Mark all affected addresses as dirty
                        for (Address address : editLabelAffectedAddresses) {
                            markObjectDirty(address);
                        }
                        editLabelAffectedAddresses.clear();
                    }
                }
            }
            
            @Override
            public void undoStackChanged(DomainObjectAdapterDB domainObj) {
                // Not needed
            }
            
            @Override
            public void undoRedoOccurred(DomainObjectAdapterDB domainObj) {
                // Not needed
            }
        };
    }
    
    /**
     * Get the symbol listener for registration with the program.
     * This listener is only used to track addresses during "Edit Label" and "Rename Local Variable" transactions.
     */
    public DomainObjectListener getListener() {
        return symbolListener;
    }
    
    /**
     * Get the transaction listener for registration with the program.
     */
    public TransactionListener getTransactionListener() {
        return transactionListener;
    }
    
    /**
     * Set whether to ignore events (e.g., during inference application).
     */
    public void setIgnoreEvents(boolean ignore) {
        this.ignoreEvents = ignore;
    }
    
    /**
     * Check if events should be ignored.
     */
    public boolean isIgnoringEvents() {
        return ignoreEvents;
    }
    
    /**
     * Handle SYMBOL_ADDED, SYMBOL_RENAMED, or SYMBOL_REMOVED events.
     * During "Edit Label" and "Rename Local Variable" transactions, tracks affected addresses.
     * After transaction completes, those addresses are marked as dirty.
     */
    private void handleSymbolEvent(ProgramChangeRecord record) {
        if (ignoreEvents) {
            return;
        }
        
        Address address = null;
        Symbol symbol = null;
        
        ProgramEvent eventType = (ProgramEvent) record.getEventType();
        
        if (eventType == SYMBOL_ADDED) {
            // getNewValue() returns the Symbol
            Object newValue = record.getNewValue();
            if (newValue instanceof Symbol) {
                symbol = (Symbol) newValue;
                address = symbol.getAddress();
            }
        } else if (eventType == SYMBOL_REMOVED) {
            // getStart() returns the address, getNewValue() returns symbolID (Long)
            address = record.getStart();
        } else if (eventType == SYMBOL_RENAMED) {
            // getObject() or getNewValue() returns the Symbol
            Object obj = record.getObject();
            if (obj instanceof Symbol) {
                symbol = (Symbol) obj;
            } else {
                Object newValue = record.getNewValue();
                if (newValue instanceof Symbol) {
                    symbol = (Symbol) newValue;
                }
            }
            if (symbol != null) {
                Address symbolAddr = symbol.getAddress();
                
                // Check if this is a variable symbol (local variable or parameter)
                if (symbolAddr != null && symbolAddr.isVariableAddress()) {
                    // This is a local variable or parameter - get the function that contains it
                    ghidra.program.model.symbol.Namespace parent = symbol.getParentNamespace();
                    if (parent instanceof Function) {
                        Function function = (Function) parent;
                        address = function.getEntryPoint(); // Mark the function as dirty
                    } 
                } else {
                    // Regular symbol (function, global variable, label) - use its address
                    address = symbolAddr;
                }
            }
        } else {
            Object obj = record.getObject();
            if (obj instanceof Symbol) {
                symbol = (Symbol) obj;
            } else {
                Object newValue = record.getNewValue();
                if (newValue instanceof Symbol) {
                    symbol = (Symbol) newValue;
                }
            }
            if (symbol != null) {
                address = symbol.getAddress();
            } else {
                address = record.getStart();
            }
        }
        
        if (address == null) {
            return;
        }

        if (trackingEditLabelTransaction) {
            // Track this address for marking as dirty when transaction completes
            synchronized (editLabelAffectedAddresses) {
                if (trackingEditLabelTransaction) {
                    // Check if this is a function or global variable we care about
                    FunctionManager funcManager = program.getFunctionManager();
                    Function function = funcManager.getFunctionAt(address);
                    
                    if (function != null) {
                        // Function rename - track the function entry point
                        if (eventType == SYMBOL_RENAMED) {
                            editLabelAffectedAddresses.add(address);
                        }
                    } else if (isGlobalVariable(program, address, symbol)) {
                        // Global variable - track it
                        editLabelAffectedAddresses.add(address);
                    }
                }
            }
            return;
        }

        handleAddressChange(address, eventType, symbol);
    }

    /**
     * Handle non-symbol program change events.
     */
    private void handleProgramChange(ProgramChangeRecord record) {
        if (ignoreEvents) {
            return;
        }

        ProgramEvent eventType = (ProgramEvent) record.getEventType();
        if (isSymbolEvent(eventType)) {
            return;
        }

        if (eventType == CODE_UNIT_PROPERTY_CHANGED && record instanceof CodeUnitPropertyChangeRecord) {
            CodeUnitPropertyChangeRecord propertyRecord = (CodeUnitPropertyChangeRecord) record;
            String propertyName = propertyRecord.getPropertyName();
            if (propertyName != null && propertyName.startsWith(PROPERTY_PREFIX)) {
                return;
            }
        }

        Address address = record.getStart();
        if (address == null) {
            return;
        }

        handleAddressChange(address, eventType, null);
    }

    private void handleAddressChange(Address address, ProgramEvent eventType, Symbol symbol) {
        Address objectAddress = getObjectAddress(address, eventType, symbol);
        if (objectAddress != null) {
            markObjectDirty(objectAddress);
            return;
        }

        if (PROPAGATE_NON_OBJECT_EVENTS.contains(eventType)) {
            propagateChangeToReferencingFunctions(address);
        }
    }

    private Address getObjectAddress(Address address, ProgramEvent eventType, Symbol symbol) {
        if (address == null) {
            return null;
        }

        FunctionManager funcManager = program.getFunctionManager();
        Function function = funcManager.getFunctionContaining(address);
        if (function != null) {
            Address entry = function.getEntryPoint();
            if (IGNORE_IN_MID_OBJECT.contains(eventType) && !entry.equals(address)) {
                return null;
            }
            return entry;
        }

        if (symbol != null) {
            ghidra.program.model.symbol.Namespace parent = symbol.getParentNamespace();
            if (parent instanceof Function) {
                return ((Function) parent).getEntryPoint();
            }
        }

        if (isGlobalVariable(program, address, symbol)) {
            Listing listing = program.getListing();
            Data data = listing.getDataContaining(address);
            return data != null ? data.getAddress() : address;
        }

        return null;
    }

    private void propagateChangeToReferencingFunctions(Address address) {
        if (address == null) {
            return;
        }

        ReferenceManager refManager = program.getReferenceManager();
        FunctionManager funcManager = program.getFunctionManager();
        for (Reference ref : refManager.getReferencesTo(address)) {
            Function function = funcManager.getFunctionContaining(ref.getFromAddress());
            if (function != null) {
                markObjectDirty(function.getEntryPoint());
            }
        }
    }

    private boolean isSymbolEvent(ProgramEvent eventType) {
        return eventType == SYMBOL_ADDED ||
            eventType == SYMBOL_RENAMED ||
            eventType == SYMBOL_REMOVED ||
            eventType == SYMBOL_SOURCE_CHANGED ||
            eventType == SYMBOL_PRIMARY_STATE_CHANGED ||
            eventType == SYMBOL_ANCHOR_FLAG_CHANGED ||
            eventType == SYMBOL_SCOPE_CHANGED ||
            eventType == SYMBOL_ASSOCIATION_ADDED ||
            eventType == SYMBOL_ASSOCIATION_REMOVED ||
            eventType == SYMBOL_DATA_CHANGED ||
            eventType == SYMBOL_ADDRESS_CHANGED;
    }
    
    /**
     * Check if an address represents a global variable (not a function or local variable).
     * 
     * @param program The program
     * @param address The address to check
     * @param symbol The symbol at the address (may be null)
     * @return true if the address is a global variable
     */
    private boolean isGlobalVariable(Program program, Address address, Symbol symbol) {
        // If we have a symbol, check if it's a local variable (has a function parent)
        if (symbol != null) {
            // Check if symbol is a local variable (has function as parent)
            ghidra.program.model.symbol.Namespace parent = symbol.getParentNamespace();
            if (parent instanceof Function) {
                return false; // Local variable, not global
            }
        }
        
        FunctionManager funcManager = program.getFunctionManager();

        Listing listing = program.getListing();
        Data data = listing.getDataContaining(address);
        if (data == null) {
            return false; // No data, not a global variable
        }

        Address dataAddress = data.getAddress();
        if (funcManager.getFunctionAt(dataAddress) != null) {
            return false; // It's a function
        }
        
        // Get symbol if not provided
        if (symbol == null) {
            ghidra.program.model.symbol.SymbolTable symbolTable = program.getSymbolTable();
            symbol = symbolTable.getPrimarySymbol(dataAddress);
        }
        
        String name = symbol != null ? symbol.getName() : null;
        
        // Include unnamed global variables that are referenced from code
        if (name == null || symbol == null || symbol.getSource() == SourceType.DEFAULT) {
            // Check if it's referenced from code
            ReferenceManager refManager = program.getReferenceManager();
            for (Reference ref : refManager.getReferencesTo(dataAddress)) {
                Function accessingFunction = funcManager.getFunctionContaining(ref.getFromAddress());
                if (accessingFunction != null) {
                    return true; // Referenced from code, treat as global variable
                }
            }
            return false;
        } else {
            // Include named global variables, excluding auto-generated string literals
            // Exclude if it looks like an auto-generated string (starts with "a" and is a string)
            boolean isAutoString = name.startsWith("a") && 
                data.getDataType().getDisplayName().contains("string") &&
                symbol.getSource() == SourceType.DEFAULT;
            
            return !isAutoString;
        }
    }
    
    /**
     * Mark an object as dirty and publish CHANGES_DETECTED event.
     */
    private void markObjectDirty(Address address) {
        if (address == null) {
            return;
        }

        if (syncStatusStorage.getSyncStatus(address)
            .map(com.zenyard.decompai.ghidra.storage.SyncStatus::isDirty)
            .orElse(false)) {
            return;
        }
        
        syncStatusStorage.markDirty(address);
        
        // Set database_dirty property (used by QueueRevisionsTask and other components)
        DecompaiProgramProperties props = new DecompaiProgramProperties(program);
        props.setString("database_dirty", "true");
        
        // Publish CHANGES_DETECTED event
        publishEvent(new DecompaiEvent(DecompaiEvent.EventType.CHANGES_DETECTED, "TrackChangesTask"));
    }
}
