package com.zenyard.ghidra.upload;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.ConnectException;
import java.net.http.HttpTimeoutException;
import java.util.concurrent.Callable;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;

import com.zenyard.ghidra.api.generated.ApiException;

/**
 * Unit tests for the static retry helpers in {@link UploadRevisionsTask}:
 * {@code isTemporaryError}, {@code retryApiRequest}, and {@code retryRevisionForever}.
 *
 * No Mockito and no Ghidra framework imports — all helpers are pure static methods
 * that accept plain Java functional interfaces.
 * All retries use {@code retryDelayMs=0} so tests complete instantly.
 */
class UploadRevisionsTaskRetryTest {

    private static final java.util.function.BooleanSupplier NOT_STOPPED = () -> false;

    // -------------------------------------------------------------------------
    // isTemporaryError — error classification
    // -------------------------------------------------------------------------

    @Test
    void isTemporary_500ApiException() {
        assertTrue(UploadRevisionsTask.isTemporaryError(new ApiException(500, "server error")));
    }

    @Test
    void isTemporary_503ApiException() {
        assertTrue(UploadRevisionsTask.isTemporaryError(new ApiException(503, "service unavailable")));
    }

    @Test
    void isTemporary_connectException() {
        Exception e = new RuntimeException(new ConnectException("refused"));
        assertTrue(UploadRevisionsTask.isTemporaryError(e));
    }

    @Test
    void isTemporary_httpTimeout() {
        Exception e = new RuntimeException(new HttpTimeoutException("timed out"));
        assertTrue(UploadRevisionsTask.isTemporaryError(e));
    }

    @Test
    void notTemporary_400ApiException() {
        assertFalse(UploadRevisionsTask.isTemporaryError(new ApiException(400, "bad request")));
    }

    @Test
    void notTemporary_404ApiException() {
        assertFalse(UploadRevisionsTask.isTemporaryError(new ApiException(404, "not found")));
    }

    @Test
    void notTemporary_genericException() {
        assertFalse(UploadRevisionsTask.isTemporaryError(new RuntimeException("unexpected")));
    }

    // -------------------------------------------------------------------------
    // retryApiRequest — bounded inner retry
    // -------------------------------------------------------------------------

    @Test
    void retryApiRequest_succeedsFirstAttempt() throws Exception {
        CountingCallable<String> callable = new CountingCallable<>(0, "ok",
                new ApiException(500, "error"));

        String result = UploadRevisionsTask.retryApiRequest(callable, "test op", 0);

        assertEquals("ok", result);
        assertEquals(1, callable.calls);
    }

    @Test
    void retryApiRequest_retriesTemporaryError_succeedsOnThird() throws Exception {
        CountingCallable<String> callable = new CountingCallable<>(2, "ok",
                new ApiException(500, "server error"));

        String result = UploadRevisionsTask.retryApiRequest(callable, "test op", 0);

        assertEquals("ok", result);
        assertEquals(3, callable.calls);
    }

    @Test
    void retryApiRequest_exhaustsMaxRetries_throws() {
        CountingCallable<String> callable = new CountingCallable<>(
                UploadRevisionsTask.MAX_RETRIES_FOR_REVISION_REQUEST,
                "ok",
                new ApiException(500, "server error"));

        assertThrows(Exception.class,
                () -> UploadRevisionsTask.retryApiRequest(callable, "test op", 0));

        assertEquals(UploadRevisionsTask.MAX_RETRIES_FOR_REVISION_REQUEST, callable.calls);
    }

    @Test
    void retryApiRequest_nonTemporaryError_raisesImmediately() {
        CountingCallable<String> callable = new CountingCallable<>(99, "ok",
                new ApiException(400, "bad request"));

        assertThrows(Exception.class,
                () -> UploadRevisionsTask.retryApiRequest(callable, "test op", 0));

        assertEquals(1, callable.calls);
    }

    // -------------------------------------------------------------------------
    // retryRevisionForever — outer infinite loop
    // -------------------------------------------------------------------------

    @Test
    void retryForever_succeedsFirstAttempt() throws Exception {
        AtomicInteger calls = new AtomicInteger();

        UploadRevisionsTask.retryRevisionForever(
                () -> calls.incrementAndGet(),
                NOT_STOPPED, 0);

        assertEquals(1, calls.get());
    }

    @Test
    void retryForever_retriesTemporaryError_succeedsEventually() throws Exception {
        AtomicInteger calls = new AtomicInteger();

        UploadRevisionsTask.retryRevisionForever(() -> {
            if (calls.incrementAndGet() <= 3) {
                throw new ApiException(500, "server error");
            }
        }, NOT_STOPPED, 0);

        assertEquals(4, calls.get());
    }

    @Test
    void retryForever_stopsWhenIsStopped() throws Exception {
        AtomicInteger calls = new AtomicInteger();
        AtomicBoolean stopped = new AtomicBoolean(false);

        UploadRevisionsTask.retryRevisionForever(() -> {
            calls.incrementAndGet();
            stopped.set(true);
            throw new ApiException(500, "server error");
        }, stopped::get, 0);

        assertEquals(1, calls.get());
    }

    @Test
    void retryForever_stopsWhenIsStoppedBeforeRetry() throws Exception {
        AtomicInteger calls = new AtomicInteger();

        // Supplier returns true after first failure so the loop exits before second attempt
        UploadRevisionsTask.retryRevisionForever(() -> {
            calls.incrementAndGet();
            throw new ApiException(500, "server error");
        }, () -> calls.get() >= 1, 0);

        assertEquals(1, calls.get());
    }

    @Test
    void retryForever_propagatesNonTemporaryError() {
        AtomicInteger calls = new AtomicInteger();

        assertThrows(ApiException.class, () ->
                UploadRevisionsTask.retryRevisionForever(() -> {
                    calls.incrementAndGet();
                    throw new ApiException(404, "not found");
                }, NOT_STOPPED, 0));

        assertEquals(1, calls.get());
    }

    // -------------------------------------------------------------------------
    // Helper: callable that fails N times then returns a result
    // -------------------------------------------------------------------------

    private static class CountingCallable<T> implements Callable<T> {
        int calls = 0;
        final int failTimes;
        final T result;
        final Exception errorToThrow;

        CountingCallable(int failTimes, T result, Exception errorToThrow) {
            this.failTimes = failTimes;
            this.result = result;
            this.errorToThrow = errorToThrow;
        }

        @Override
        public T call() throws Exception {
            calls++;
            if (calls <= failTimes) throw errorToThrow;
            return result;
        }
    }
}
