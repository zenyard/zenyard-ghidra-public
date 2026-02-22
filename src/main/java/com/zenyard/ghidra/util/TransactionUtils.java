package com.zenyard.ghidra.util;

import java.util.concurrent.Callable;

import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

/**
 * Transaction helpers for program modifications.
 */
public final class TransactionUtils {
    private TransactionUtils() {}

    public static void runInTransaction(Program program, String description, Runnable action) {
        if (program == null || program.isClosed()) {
            return;
        }
        int txId;
        try {
            txId = program.startTransaction(description);
        } catch (RuntimeException e) {
            // Program is closing / DB is closed / transaction manager terminated.
            // Caller should treat this as "cannot modify now".
            Msg.debug(TransactionUtils.class, "Failed to start transaction '" + description
                + "': " + e.getMessage());
            String msg = String.valueOf(e.getMessage());
            if (msg.contains("Database is closed") || msg.contains("Transaction has been terminated")) {
                return;
            }
            throw e;
        }

        RuntimeException primary = null;
        try {
            action.run();
        } catch (RuntimeException e) {
            primary = e;
        } finally {
            try {
                program.endTransaction(txId, primary == null);
            } catch (RuntimeException endEx) {
                // Ghidra may forcibly abort/terminate transactions during shutdown; in that
                // case endTransaction can throw. Preserve the original exception if any.
                String msg = String.valueOf(endEx.getMessage());
                if (msg.contains("Attempted to end Transaction")
                    || msg.contains("Database is closed")
                    || msg.contains("Transaction has been terminated")) {
                    Msg.debug(TransactionUtils.class, "Ignoring endTransaction failure for '" + description
                        + "': " + endEx.getMessage());
                    return;
                }
                if (primary != null) {
                    primary.addSuppressed(endEx);
                } else {
                    throw endEx;
                }
            }
        }

        if (primary != null) {
            throw primary;
        }
    }

    public static <T> T callInTransaction(Program program, String description, Callable<T> action) {
        if (program == null || program.isClosed()) {
            return null;
        }
        int txId;
        try {
            txId = program.startTransaction(description);
        } catch (RuntimeException e) {
            Msg.debug(TransactionUtils.class, "Failed to start transaction '" + description
                + "': " + e.getMessage());
            String msg = String.valueOf(e.getMessage());
            if (msg.contains("Database is closed") || msg.contains("Transaction has been terminated")) {
                return null;
            }
            throw e;
        }

        Exception primary = null;
        T result = null;
        try {
            result = action.call();
        } catch (Exception e) {
            primary = e;
        } finally {
            try {
                program.endTransaction(txId, primary == null);
            } catch (RuntimeException endEx) {
                String msg = String.valueOf(endEx.getMessage());
                if (msg.contains("Attempted to end Transaction")
                    || msg.contains("Database is closed")
                    || msg.contains("Transaction has been terminated")) {
                    Msg.debug(TransactionUtils.class, "Ignoring endTransaction failure for '" + description
                        + "': " + endEx.getMessage());
                    return result;
                }
                if (primary != null) {
                    primary.addSuppressed(endEx);
                } else {
                    throw endEx;
                }
            }
        }

        if (primary != null) {
            throw new RuntimeException(primary);
        }
        return result;
    }
}
