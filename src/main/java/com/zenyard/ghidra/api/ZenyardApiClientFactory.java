package com.zenyard.ghidra.api;

import com.zenyard.ghidra.api.generated.ApiClient;
import com.zenyard.ghidra.config.ZenyardOptions;
import java.net.http.HttpRequest;

/**
 * Factory for creating and configuring the generated OpenAPI ApiClient.
 * Similar to IDA extension's open_api_client() function.
 */
public class ZenyardApiClientFactory {
    
    /**
     * Create and configure an ApiClient from ZenyardOptions.
     * 
     * @param options The configuration options
     * @return Configured ApiClient instance
     */
    public static ApiClient createApiClient(ZenyardOptions options) {
        if (!options.isConfigured()) {
            throw new IllegalStateException("Zenyard options are not configured");
        }
        
        String baseUrl = options.getServerUrl();
        // Remove trailing slash if present
        if (baseUrl.endsWith("/")) {
            baseUrl = baseUrl.substring(0, baseUrl.length() - 1);
        }
        
        ApiClient apiClient = new ApiClient();
        // Use updateBaseUri() to properly parse the full URL and set scheme, host, port, and basePath
        apiClient.updateBaseUri(baseUrl);
        
        // Set API key via request interceptor
        String apiKey = options.getApiKey();
        apiClient.setRequestInterceptor((HttpRequest.Builder builder) -> {
            builder.header("X-API-Key", apiKey);
        });
        
        // Note: The generated client may have additional configuration options
        // that can be set here if needed (e.g., SSL verification, timeouts, etc.)
        
        return apiClient;
    }
}

