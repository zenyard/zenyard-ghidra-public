package com.zenyard.ghidra.api;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.concurrent.CompletableFuture;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.zenyard.ghidra.api.exceptions.ZenyardApiException;
import com.zenyard.ghidra.api.exceptions.ZenyardUnauthorizedException;
import com.zenyard.ghidra.api.exceptions.ZenyardForbiddenException;
import com.zenyard.ghidra.api.models.AddObjectsToCurrentRevisionParams;
import com.zenyard.ghidra.api.models.BinaryStatus;
import com.zenyard.ghidra.api.models.CreateRevisionParams;
import com.zenyard.ghidra.api.models.FinishAndAnalyzeCurrentRevisionParams;
import com.zenyard.ghidra.api.models.GetInferencesResponse;
import com.zenyard.ghidra.api.models.HealthResponse;
import com.zenyard.ghidra.api.models.PostBinaryBody;
import com.zenyard.ghidra.api.models.PostBinaryResponse;
import java.util.UUID;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

/**
 * Thin wrapper over HTTP client for Zenyard API.
 * Handles auth, base URL, and error normalization.
 * 
 * NOTE: mirrors functionality in zenyard_client/api_client.py and zenyard_client/zenyard_api/*.py
 * This is a minimal implementation; candidate for future OpenAPI-based generation.
 */
public class ZenyardApiClient {
    
    private static final String API_KEY_HEADER = "X-API-Key";
    private static final String CONTENT_TYPE_HEADER = "Content-Type";
    private static final String APPLICATION_JSON = "application/json";
    private static final Duration DEFAULT_TIMEOUT = Duration.ofSeconds(30);
    
    private final HttpClient httpClient;
    private final String baseUrl;
    private final String apiKey;
    private final Gson gson;
    
    public ZenyardApiClient(String baseUrl, String apiKey) {
        this.baseUrl = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
        this.apiKey = apiKey;
        this.httpClient = HttpClient.newBuilder()
            .connectTimeout(DEFAULT_TIMEOUT)
            .followRedirects(HttpClient.Redirect.NORMAL) // Follow redirects (301, 302, 307, 308)
            .build();
        this.gson = new GsonBuilder()
            .setPrettyPrinting()
            .create();
    }
    
    /**
     * Check API health/connectivity.
     * 
     * @return Health response
     * @throws ZenyardApiException if the request fails
     */
    public CompletableFuture<HealthResponse> health() {
        return sendRequest("GET", "/health", null, HealthResponse.class);
    }
    
    /**
     * Send an HTTP request and parse the response.
     * 
     * @param method HTTP method
     * @param path API path (relative to base URL)
     * @param body Request body (will be serialized as JSON)
     * @param responseClass Response class for deserialization
     * @return CompletableFuture with the parsed response
     */
    private <T> CompletableFuture<T> sendRequest(
            String method,
            String path,
            Object body,
            Class<T> responseClass) {
        
        URI uri = URI.create(baseUrl + path);
        
        HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
            .uri(uri)
            .header(API_KEY_HEADER, apiKey)
            .timeout(DEFAULT_TIMEOUT);
        
        if (body != null) {
            String jsonBody = gson.toJson(body);
            requestBuilder
                .header(CONTENT_TYPE_HEADER, APPLICATION_JSON)
                .method(method, HttpRequest.BodyPublishers.ofString(jsonBody));
        } else {
            requestBuilder.method(method, HttpRequest.BodyPublishers.noBody());
        }
        
        HttpRequest request = requestBuilder.build();
        
        CompletableFuture<T> future = new CompletableFuture<>();
        
        httpClient.sendAsync(request, HttpResponse.BodyHandlers.ofString())
            .thenAccept(response -> {
                try {
                    int statusCode = response.statusCode();
                    
                    // Handle error status codes
                    if (statusCode == 401) {
                        future.completeExceptionally(
                            new ZenyardUnauthorizedException("Unauthorized - check your API key"));
                        return;
                    } else if (statusCode == 403) {
                        future.completeExceptionally(
                            new ZenyardForbiddenException("Forbidden - insufficient permissions"));
                        return;
                    } else if (statusCode == 307 || statusCode == 308) {
                        // Temporary/Permanent Redirect - should be handled by HttpClient, but if we get here,
                        // it might be a redirect that requires special handling (e.g., POST to GET)
                        String location = response.headers().firstValue("Location").orElse("unknown");
                        future.completeExceptionally(
                            new ZenyardApiException(
                                "Redirect error (status " + statusCode + "): Server redirected to " + location 
                                + ". Please check if the server URL is correct: " + baseUrl));
                        return;
                    } else if (statusCode < 200 || statusCode >= 300) {
                        future.completeExceptionally(
                            new ZenyardApiException(
                                "API request failed with status " + statusCode + ": " + response.body()));
                        return;
                    }
                    
                    // Parse response
                    String responseBody = response.body();
                    if (responseBody == null || responseBody.trim().isEmpty()) {
                        future.complete(null);
                        return;
                    }
                    
                    try {
                        T result = gson.fromJson(responseBody, responseClass);
                        future.complete(result);
                    } catch (Exception e) {
                        future.completeExceptionally(
                            new ZenyardApiException(
                                "Failed to parse API response: " + e.getMessage(), e));
                    }
                } catch (Exception e) {
                    future.completeExceptionally(e);
                }
            })
            .exceptionally(throwable -> {
                Throwable cause = throwable.getCause();
                if (cause instanceof ZenyardApiException) {
                    future.completeExceptionally(cause);
                } else if (throwable instanceof IOException || cause instanceof IOException) {
                    future.completeExceptionally(
                        new ZenyardApiException(
                            "Network error: " + throwable.getMessage(), throwable));
                } else {
                    future.completeExceptionally(
                        new ZenyardApiException(
                            "Unexpected error: " + throwable.getMessage(), throwable));
                }
                return null;
            });
        
        return future;
    }
    
    /**
     * Send a POST request.
     */
    public <TRequest, TResponse> CompletableFuture<TResponse> post(
            String path,
            TRequest body,
            Class<TResponse> responseClass) {
        return sendRequest("POST", path, body, responseClass);
    }
    
    /**
     * Send a GET request.
     */
    public <TResponse> CompletableFuture<TResponse> get(
            String path,
            Class<TResponse> responseClass) {
        return sendRequest("GET", path, null, responseClass);
    }
    
    /**
     * Send a PUT request.
     */
    public <TRequest, TResponse> CompletableFuture<TResponse> put(
            String path,
            TRequest body,
            Class<TResponse> responseClass) {
        return sendRequest("PUT", path, body, responseClass);
    }
    
    /**
     * Get the base URL.
     */
    public String getBaseUrl() {
        return baseUrl;
    }
    
    /**
     * Create a binary.
     * 
     * @param body Request body with name and details
     * @return Response with binary_id
     */
    public CompletableFuture<PostBinaryResponse> createBinary(PostBinaryBody body) {
        return post("/binaries", body, PostBinaryResponse.class);
    }
    
    /**
     * Upload original file (binary, idb, or dyld).
     * 
     * @param binaryId Binary ID
     * @param name File name
     * @param data File data (will be sent as multipart/form-data)
     * @param type File type ("binary", "idb", or "dyld")
     * @return CompletableFuture that completes when upload is done
     */
    public CompletableFuture<Void> uploadOriginalFile(UUID binaryId, String name, byte[] data, String type) {
        // Create multipart/form-data request
        String boundary = "----WebKitFormBoundary" + System.currentTimeMillis();
        String contentType = "multipart/form-data; boundary=" + boundary;
        
        // Build multipart body
        // First part: file data
        String filePartHeader = "--" + boundary + "\r\n" 
            + "Content-Disposition: form-data; name=\"data\"; filename=\"" + name + "\"\r\n" 
            + "Content-Type: application/octet-stream\r\n\r\n";
        byte[] filePartHeaderBytes = filePartHeader.getBytes(StandardCharsets.UTF_8);
        
        // Second part: type parameter
        String typePart = "\r\n--" + boundary + "\r\n" 
            + "Content-Disposition: form-data; name=\"type\"\r\n\r\n" 
            + type + "\r\n" 
            + "--" + boundary + "--\r\n";
        byte[] typePartBytes = typePart.getBytes(StandardCharsets.UTF_8);
        
        // Combine all parts
        byte[] fullBody = new byte[filePartHeaderBytes.length + data.length + typePartBytes.length];
        int offset = 0;
        System.arraycopy(filePartHeaderBytes, 0, fullBody, offset, filePartHeaderBytes.length);
        offset += filePartHeaderBytes.length;
        System.arraycopy(data, 0, fullBody, offset, data.length);
        offset += data.length;
        System.arraycopy(typePartBytes, 0, fullBody, offset, typePartBytes.length);
        
        URI uri = URI.create(baseUrl + "/binaries/" + binaryId + "/original_files/" 
                            + URLEncoder.encode(name, StandardCharsets.UTF_8));
        
        HttpRequest request = HttpRequest.newBuilder()
            .uri(uri)
            .header(API_KEY_HEADER, apiKey)
            .header(CONTENT_TYPE_HEADER, contentType)
            .timeout(DEFAULT_TIMEOUT)
            .PUT(BodyPublishers.ofByteArray(fullBody))
            .build();
        
        CompletableFuture<Void> future = new CompletableFuture<>();
        
        httpClient.sendAsync(request, HttpResponse.BodyHandlers.ofString())
            .thenAccept(response -> {
                int statusCode = response.statusCode();
                if (statusCode == 401) {
                    future.completeExceptionally(
                        new ZenyardUnauthorizedException("Unauthorized - check your API key"));
                } else if (statusCode == 403) {
                    future.completeExceptionally(
                        new ZenyardForbiddenException("Forbidden - insufficient permissions"));
                } else if (statusCode < 200 || statusCode >= 300) {
                    future.completeExceptionally(
                        new ZenyardApiException(
                            "API request failed with status " + statusCode + ": " + response.body()));
                } else {
                    future.complete(null);
                }
            })
            .exceptionally(throwable -> {
                Throwable cause = throwable.getCause();
                if (cause instanceof ZenyardApiException) {
                    future.completeExceptionally(cause);
                } else if (throwable instanceof IOException || cause instanceof IOException) {
                    future.completeExceptionally(
                        new ZenyardApiException(
                            "Network error: " + throwable.getMessage(), throwable));
                } else {
                    future.completeExceptionally(
                        new ZenyardApiException(
                            "Unexpected error: " + throwable.getMessage(), throwable));
                }
                return null;
            });
        
        return future;
    }
    
    /**
     * Create a revision.
     * 
     * @param binaryId Binary ID
     * @param params Revision parameters
     * @return CompletableFuture that completes when revision is created
     */
    public CompletableFuture<Void> createRevision(UUID binaryId, CreateRevisionParams params) {
        return post("/binaries/" + binaryId + "/revisions/create", params, Void.class);
    }
    
    /**
     * Add objects to the current revision.
     * 
     * @param binaryId Binary ID
     * @param params Parameters with objects to add
     * @return CompletableFuture that completes when objects are added
     */
    public CompletableFuture<Void> addObjectsToRevision(UUID binaryId, AddObjectsToCurrentRevisionParams params) {
        return post("/binaries/" + binaryId + "/revisions/add_objects_to_current_revision", params, Void.class);
    }
    
    /**
     * Finish and analyze the current revision.
     * 
     * @param binaryId Binary ID
     * @param params Parameters with analyze_dependents flag
     * @return CompletableFuture that completes when revision is finished
     */
    public CompletableFuture<Void> finishAndAnalyzeRevision(UUID binaryId, FinishAndAnalyzeCurrentRevisionParams params) {
        return post("/binaries/" + binaryId + "/revisions/finish_and_analyze_current_revision", params, Void.class);
    }
    
    /**
     * Get inferences for a revision.
     * 
     * @param binaryId Binary ID
     * @param revisionNumber Revision number
     * @param cursor Cursor for pagination (optional)
     * @param limit Maximum number of inferences to return (optional)
     * @return Response with inferences, cursor, and has_next flag
     */
    public CompletableFuture<GetInferencesResponse> getInferences(UUID binaryId, int revisionNumber, Integer cursor, Integer limit) {
        StringBuilder path = new StringBuilder("/binaries/");
        path.append(binaryId);
        path.append("/revisions/");
        path.append(revisionNumber);
        path.append("/inferences");
        
        boolean firstParam = true;
        if (cursor != null) {
            path.append(firstParam ? "?" : "&");
            path.append("cursor=").append(cursor);
            firstParam = false;
        }
        if (limit != null) {
            path.append(firstParam ? "?" : "&");
            path.append("limit=").append(limit);
        }
        
        return get(path.toString(), GetInferencesResponse.class);
    }
    
    /**
     * Get detailed status of binary analysis.
     * 
     * @param binaryId Binary ID
     * @return Binary status with revision analyses
     */
    public CompletableFuture<BinaryStatus> getDetailedStatus(UUID binaryId) {
        return get("/binaries/" + binaryId + "/detailed_status", BinaryStatus.class);
    }
}

