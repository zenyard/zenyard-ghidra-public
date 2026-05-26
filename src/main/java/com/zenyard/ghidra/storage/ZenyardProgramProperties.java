package com.zenyard.ghidra.storage;

import ghidra.framework.options.Options;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

/**
 * Simple wrapper around Program options for storing plugin data.
 *
 * Uses DomainObject-backed Options to follow save/discard semantics.
 */
public class ZenyardProgramProperties {
    
    private final Program program;
    private final Options options;
    
    public ZenyardProgramProperties(Program program) {
        this.program = program;
        this.options = program.getOptions("Zenyard");
    }
    
    /**
     * Store a string property.
     * In Ghidra, property maps must be created within a transaction.
     */
    public void setString(String key, String value) {
        if (program == null || program.isClosed()) {
            return;
        }

        int transactionId;
        try {
            transactionId = program.startTransaction("Set Zenyard property: " + key);
        } catch (RuntimeException e) {
            // Happens during program shutdown (terminated transaction manager / DB closed).
            // Do not escalate; property writes are best-effort.
            Msg.debug(this, "Skipping property write during shutdown: " + key + " (" + e.getMessage() + ")");
            return;
        }

        boolean success = false;
        RuntimeException primary = null;
        try {
            options.setString(key, value);
            success = true;
        } catch (RuntimeException e) {
            primary = e;
        } finally {
            try {
                program.endTransaction(transactionId, success);
            } catch (RuntimeException endEx) {
                if (primary != null) {
                    primary.addSuppressed(endEx);
                } else {
                    // Shutdown path; ignore.
                    Msg.debug(this, "endTransaction failed for property write " + key + ": " + endEx.getMessage());
                }
            }
        }

        if (primary != null) {
            String msg = String.valueOf(primary.getMessage());
            if (msg.contains("Database is closed") || msg.contains("Transaction has been terminated")) {
                Msg.debug(this, "Skipping property write during shutdown: " + key + " (" + msg + ")");
                return;
            }
            Msg.error(this, "Failed to set string property: " + primary.getMessage(), primary);
        }
    }
    
    /**
     * Write multiple string properties in a single transaction.
     */
    public void setStrings(java.util.Map<String, String> entries) {
        if (program == null || program.isClosed() || entries.isEmpty()) {
            return;
        }

        int transactionId;
        try {
            transactionId = program.startTransaction("Set Zenyard properties batch");
        } catch (RuntimeException e) {
            Msg.debug(this, "Skipping batch property write during shutdown: " + e.getMessage());
            return;
        }

        boolean success = false;
        RuntimeException primary = null;
        try {
            for (java.util.Map.Entry<String, String> entry : entries.entrySet()) {
                options.setString(entry.getKey(), entry.getValue());
            }
            success = true;
        } catch (RuntimeException e) {
            primary = e;
        } finally {
            try {
                program.endTransaction(transactionId, success);
            } catch (RuntimeException endEx) {
                if (primary != null) {
                    primary.addSuppressed(endEx);
                } else {
                    Msg.debug(this, "endTransaction failed for batch property write: " + endEx.getMessage());
                }
            }
        }

        if (primary != null) {
            String msg = String.valueOf(primary.getMessage());
            if (msg.contains("Database is closed") || msg.contains("Transaction has been terminated")) {
                Msg.debug(this, "Skipping batch property write during shutdown: " + msg);
                return;
            }
            Msg.error(this, "Failed batch property write: " + primary.getMessage(), primary);
        }
    }

    /**
     * Get a string property.
     */
    public String getString(String key) {
        return options.getString(key, null);
    }
    
    /**
     * Store an integer property.
     * In Ghidra, property maps must be created within a transaction.
     */
    public void setInt(String key, int value) {
        if (program == null || program.isClosed()) {
            return;
        }

        int transactionId;
        try {
            transactionId = program.startTransaction("Set Zenyard property: " + key);
        } catch (RuntimeException e) {
            Msg.debug(this, "Skipping property write during shutdown: " + key + " (" + e.getMessage() + ")");
            return;
        }

        boolean success = false;
        RuntimeException primary = null;
        try {
            options.setString(key, String.valueOf(value));
            success = true;
        } catch (RuntimeException e) {
            primary = e;
        } finally {
            try {
                program.endTransaction(transactionId, success);
            } catch (RuntimeException endEx) {
                if (primary != null) {
                    primary.addSuppressed(endEx);
                } else {
                    Msg.debug(this, "endTransaction failed for property write " + key + ": " + endEx.getMessage());
                }
            }
        }

        if (primary != null) {
            String msg = String.valueOf(primary.getMessage());
            if (msg.contains("Database is closed") || msg.contains("Transaction has been terminated")) {
                Msg.debug(this, "Skipping property write during shutdown: " + key + " (" + msg + ")");
                return;
            }
            Msg.error(this, "Failed to set integer property: " + primary.getMessage(), primary);
        }
    }
    
    /**
     * Remove a property by key (delegates to Options.removeOption inside a transaction).
     */
    public void removeOption(String key) {
        if (program == null || program.isClosed()) {
            return;
        }

        int transactionId;
        try {
            transactionId = program.startTransaction("Remove Zenyard property: " + key);
        } catch (RuntimeException e) {
            Msg.debug(this, "Skipping property remove during shutdown: " + key + " (" + e.getMessage() + ")");
            return;
        }

        boolean success = false;
        RuntimeException primary = null;
        try {
            if (options.contains(key)) {
                options.removeOption(key);
            }
            success = true;
        } catch (RuntimeException e) {
            primary = e;
        } finally {
            try {
                program.endTransaction(transactionId, success);
            } catch (RuntimeException endEx) {
                if (primary != null) {
                    primary.addSuppressed(endEx);
                } else {
                    Msg.debug(this, "endTransaction failed for property remove " + key + ": " + endEx.getMessage());
                }
            }
        }

        if (primary != null) {
            String msg = String.valueOf(primary.getMessage());
            if (msg.contains("Database is closed") || msg.contains("Transaction has been terminated")) {
                Msg.debug(this, "Skipping property remove during shutdown: " + key + " (" + msg + ")");
                return;
            }
            Msg.error(this, "Failed to remove property: " + primary.getMessage(), primary);
        }
    }

    /**
     * Get an integer property.
     */
    public Integer getInt(String key) {
        String cachedValue = options.getString(key, null);
        if (cachedValue != null && !cachedValue.isEmpty()) {
            try {
                return Integer.parseInt(cachedValue);
            } catch (NumberFormatException e) {
                return null;
            }
        }
        return null;
    }
}

