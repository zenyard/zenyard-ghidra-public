package com.zenyard.decompai.ghidra.util;

import java.util.concurrent.Callable;

import ghidra.program.model.listing.Program;

/**
 * Transaction helpers for program modifications.
 */
public final class TransactionUtils {
    private TransactionUtils() {}

    public static void runInTransaction(Program program, String description, Runnable action) {
        int txId = program.startTransaction(description);
        try {
            action.run();
            program.endTransaction(txId, true);
        } catch (RuntimeException e) {
            program.endTransaction(txId, false);
            throw e;
        }
    }

    public static <T> T callInTransaction(Program program, String description, Callable<T> action) {
        int txId = program.startTransaction(description);
        try {
            T result = action.call();
            program.endTransaction(txId, true);
            return result;
        } catch (Exception e) {
            program.endTransaction(txId, false);
            throw new RuntimeException(e);
        }
    }
}
