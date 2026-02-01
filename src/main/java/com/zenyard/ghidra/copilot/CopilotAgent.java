package com.zenyard.ghidra.copilot;

import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import dev.langchain4j.data.message.AiMessage;
import dev.langchain4j.data.message.UserMessage;
import dev.langchain4j.memory.ChatMemory;
import dev.langchain4j.model.chat.ChatModel;
import dev.langchain4j.model.chat.StreamingChatModel;
import dev.langchain4j.model.chat.request.ChatRequest;
import dev.langchain4j.model.openai.OpenAiChatModel;
import dev.langchain4j.model.openai.OpenAiStreamingChatModel;
import dev.langchain4j.model.anthropic.AnthropicChatModel;
import dev.langchain4j.model.anthropic.AnthropicStreamingChatModel;
import dev.langchain4j.model.output.Response;
import dev.langchain4j.service.AiServices;
import dev.langchain4j.service.TokenStream;

import com.google.auth.oauth2.ServiceAccountCredentials;
import com.google.auth.oauth2.GoogleCredentials;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Copilot agent using LangChain4j AI Services pattern.
 * 
 * Mirrors the agent creation from IDA's copilot_task.py.
 */
public class CopilotAgent {
    
    // System prompt matches IDA's AGENT_SYSTEM_PROMPT
    private static final String SYSTEM_PROMPT = """
        You are a reverse engineering ai assistant.
        You accomplish a given task iteratively, breaking it down into clear steps and working through them methodically.

        1. Analyze the user's task and set clear, achievable goals to accomplish it. Prioritize these goals in a logical order.
        2. Work through these goals sequentially, utilizing available tools one at a time as necessary. Each goal should correspond to a distinct step in your problem-solving process. You will be informed on the work completed and what's remaining as you go.
        3. The user may provide feedback, which you can use to make improvements and try again. But DO NOT continue in pointless back and forth conversations, i.e. don't end your responses with questions or offers for further assistance.
        4. When using paginated tools, do NOT inform the user about pagination details.
        """;
    
    private interface CopilotAgentService {
        @dev.langchain4j.service.SystemMessage(SYSTEM_PROMPT)
        @dev.langchain4j.service.UserMessage("{{message}}")
        TokenStream chat(String message);
    }
    
    private final CopilotAgentService agent;
    private final StreamingChatModel chatModel;
    private final ChatMemory chatMemory;
    private final CopilotStreamHandler streamHandler;
    private CopilotSummarizer summarizer; // Optional summarizer
    private CopilotMemory copilotMemory; // Reference to CopilotMemory for summarization
    
    public CopilotAgent(
            StreamingChatModel chatModel,
            ChatMemory chatMemory,
            List<Object> tools,
            CopilotStreamHandler streamHandler) {
        
        this.chatModel = chatModel;
        this.chatMemory = chatMemory;
        this.streamHandler = streamHandler;
        this.summarizer = null; // Set via setSummarizer() if needed
        this.copilotMemory = null; // Set via setCopilotMemory() if needed
        
        // Build AI Service with tools and memory
        // Note: Streaming is handled via the streamHandler when calling chat()
        this.agent = AiServices.builder(CopilotAgentService.class)
            .streamingChatModel(chatModel)
            .tools(tools.toArray())
            .chatMemory(chatMemory)
            .build();
    }
    
    /**
     * Send a message to the agent and get a response.
     * Uses streaming if streamHandler is configured and chatModel supports streaming.
     */
    public Response<AiMessage> chat(String message) {
        try {
            // Reset stream handler for new message
            if (streamHandler != null) {
                streamHandler.reset();
            }
            
            TokenStream stream = agent.chat(message);
            if (stream == null) {
                throw new RuntimeException("Streaming model did not return a token stream");
            }

            AtomicReference<Response<AiMessage>> responseHolder = new AtomicReference<>();
            AtomicReference<Throwable> errorHolder = new AtomicReference<>();
            CountDownLatch completion = new CountDownLatch(1);

            stream.onPartialResponse(partial -> {
                if (streamHandler != null) {
                    streamHandler.onPartialResponse(partial);
                }
            });
            stream.onCompleteResponse(completeResponse -> {
                responseHolder.set(Response.from(
                    completeResponse.aiMessage(),
                    completeResponse.metadata() != null ? completeResponse.metadata().tokenUsage() : null,
                    completeResponse.metadata() != null ? completeResponse.metadata().finishReason() : null
                ));
                if (streamHandler != null) {
                    streamHandler.onCompleteResponse(completeResponse);
                }
                completion.countDown();
            });
            stream.onError(error -> {
                errorHolder.set(error);
                if (streamHandler != null) {
                    streamHandler.onError(error);
                }
                completion.countDown();
            });
            stream.start();

            boolean finished = completion.await(120, TimeUnit.SECONDS);
            if (!finished) {
                throw new RuntimeException("Streaming response did not complete in time");
            }
            if (errorHolder.get() != null) {
                Throwable error = errorHolder.get();
                throw error instanceof Exception ? (Exception) error : new RuntimeException(error);
            }
            Response<AiMessage> response = responseHolder.get();
            if (response == null) {
                throw new RuntimeException("Streaming response did not produce a final message");
            }
            if (summarizer != null && copilotMemory != null) {
                summarizer.summarizeIfNeeded(copilotMemory);
            }
            return response;
        } catch (Exception e) {
            throw new RuntimeException("Error during agent chat: " + e.getMessage(), e);
        }
    }
    
    /**
     * Clear the conversation memory.
     */
    public void clearMemory() {
        chatMemory.clear();
    }
    
    /**
     * Get the chat memory.
     */
    public ChatMemory getChatMemory() {
        return chatMemory;
    }
    
    /**
     * Set the summarizer and memory for this agent.
     */
    public void setSummarizer(CopilotSummarizer summarizer, CopilotMemory copilotMemory) {
        this.summarizer = summarizer;
        this.copilotMemory = copilotMemory;
    }
    
    // Shared rate limiter instance (15 requests per 60 seconds)
    private static final CopilotRateLimiter RATE_LIMITER = new CopilotRateLimiter();
    
    /**
     * Create a ChatModel from CopilotConfig.
     * Applies rate limiting (15 requests per 60 seconds) to all providers.
     */
    public static ChatModel createChatModel(CopilotConfig config) {
        String provider = config.getModelProvider();
        String modelName = config.getModelName();
        
        ChatModel baseModel;
        
        switch (provider) {
            case "openai":
                baseModel = buildOpenAiModel(config, modelName, false);
                break;
            case "openai-compatible":
            case "openai_compatible":
                baseModel = buildOpenAiCompatibleModel(config, modelName, false);
                break;
            
            case "anthropic":
                // AnthropicChatModel implements ChatModel in langchain4j 1.10.0
                String anthropicKey = requireApiKey(config);
                AnthropicChatModel.AnthropicChatModelBuilder anthropicBuilder = AnthropicChatModel.builder()
                    .apiKey(anthropicKey)
                    .modelName(modelName)
                    .temperature(getDoubleParam(config, 0.7, "temperature"))
                    .maxTokens(getIntParam(config, 4096, "max_tokens", "maxTokens"))
                    .timeout(getTimeoutParam(config, 30));
                applyAnthropicOptionalParams(anthropicBuilder, config);
                baseModel = (ChatModel) anthropicBuilder.build();
                break;
            
            case "google_vertex_ai":
            case "google_anthropic_vertex":
                // Handle service account credentials (like IDA implementation)
                GoogleCredentials credentials = createGoogleCredentials(config);
                
                dev.langchain4j.model.vertexai.gemini.VertexAiGeminiChatModel.VertexAiGeminiChatModelBuilder builder = 
                    dev.langchain4j.model.vertexai.gemini.VertexAiGeminiChatModel.builder()
                    .project(getStringParam(config, "project_id", "project"))
                    .location(getStringParam(config, "location", "region", "us-central1"))
                    .modelName(modelName)
                    .temperature((float) getDoubleParam(config, 0.7, "temperature"))
                    .maxOutputTokens(getIntParam(config, 4096, "max_tokens", "maxTokens"));
                
                if (credentials != null) {
                    builder.credentials(credentials);
                }
                
                baseModel = builder.build();
                break;
            
            default:
                baseModel = buildOpenAiCompatibleModel(config, modelName, true);
                break;
        }
        
        // Wrap with rate limiter
        return new RateLimitedChatModel(baseModel, RATE_LIMITER);
    }

    public static StreamingChatModel createStreamingChatModel(CopilotConfig config) {
        String provider = config.getModelProvider();
        String modelName = config.getModelName();

        switch (provider) {
            case "openai":
                return buildOpenAiStreamingModel(config, modelName, false, null);
            case "openai-compatible":
            case "openai_compatible":
                return buildOpenAiStreamingModel(config, modelName, true, null);
            case "anthropic":
                return buildAnthropicStreamingModel(config, modelName, null);
            case "google_vertex_ai":
            case "google_anthropic_vertex":
                return buildVertexStreamingModel(config, modelName, null);
            default:
                throw new IllegalArgumentException(
                    "Streaming is not supported for provider: " + provider);
        }
    }
    
    /**
     * Create a ChatModel for summarization from CopilotConfig.
     * Similar to createChatModel() but with maxTokens(10_000) constraint.
     * Mirrors IDA's llm_for_summarization creation.
     */
    public static ChatModel createSummarizationModel(CopilotConfig config) {
        String provider = config.getModelProvider();
        String modelName = config.getModelName();
        
        ChatModel baseModel;
        
        switch (provider) {
            case "openai":
                baseModel = buildOpenAiModel(config, modelName, false, 10_000);
                break;
            case "openai-compatible":
            case "openai_compatible":
                baseModel = buildOpenAiCompatibleModel(config, modelName, false, 10_000);
                break;
            
            case "anthropic":
                // AnthropicChatModel implements ChatModel in langchain4j 1.10.0
                String summarizationKey = requireApiKey(config);
                AnthropicChatModel.AnthropicChatModelBuilder summarizationBuilder = AnthropicChatModel.builder()
                    .apiKey(summarizationKey)
                    .modelName(modelName)
                    .temperature(getDoubleParam(config, 0.7, "temperature"))
                    .maxTokens(10_000) // Summarization max tokens (matches IDA)
                    .timeout(getTimeoutParam(config, 30));
                applyAnthropicOptionalParams(summarizationBuilder, config);
                baseModel = (ChatModel) summarizationBuilder.build();
                break;
            
            case "google_vertex_ai":
            case "google_anthropic_vertex":
                // Handle service account credentials (like IDA implementation)
                GoogleCredentials credentials = createGoogleCredentials(config);
                
                dev.langchain4j.model.vertexai.gemini.VertexAiGeminiChatModel.VertexAiGeminiChatModelBuilder builder = 
                    dev.langchain4j.model.vertexai.gemini.VertexAiGeminiChatModel.builder()
                    .project(getStringParam(config, "project_id", "project"))
                    .location(getStringParam(config, "location", "region", "us-central1"))
                    .modelName(modelName)
                    .temperature((float) getDoubleParam(config, 0.7, "temperature"))
                    .maxOutputTokens(10_000); // Summarization max tokens (matches IDA)
                
                if (credentials != null) {
                    builder.credentials(credentials);
                }
                
                baseModel = builder.build();
                break;
            
            default:
                baseModel = buildOpenAiCompatibleModel(config, modelName, true, 10_000);
                break;
        }
        
        // Wrap with rate limiter (same rate limiter as main model)
        return new RateLimitedChatModel(baseModel, RATE_LIMITER);
    }

    public static StreamingChatModel createStreamingSummarizationModel(CopilotConfig config) {
        String provider = config.getModelProvider();
        String modelName = config.getModelName();

        switch (provider) {
            case "openai":
                return buildOpenAiStreamingModel(config, modelName, false, 10_000);
            case "openai-compatible":
            case "openai_compatible":
                return buildOpenAiStreamingModel(config, modelName, true, 10_000);
            case "anthropic":
                return buildAnthropicStreamingModel(config, modelName, 10_000);
            case "google_vertex_ai":
            case "google_anthropic_vertex":
                return buildVertexStreamingModel(config, modelName, 10_000);
            default:
                throw new IllegalArgumentException(
                    "Streaming summarization is not supported for provider: " + provider);
        }
    }
    
    /**
     * Create Google credentials from service account info in config.
     * Mirrors the credential creation in IDA's copilot_task.py.
     */
    private static GoogleCredentials createGoogleCredentials(CopilotConfig config) {
        try {
            // Try to get credentials from additional_params
            @SuppressWarnings("unchecked")
            Map<String, Object> credentialsData = config.getAdditionalParam("credentials", Map.class);
            if (credentialsData == null) {
                String credentialsJson = getStringParam(config, "credentials");
                if (credentialsJson != null && !credentialsJson.isBlank()) {
                    com.google.gson.Gson gson = new com.google.gson.Gson();
                    @SuppressWarnings("unchecked")
                    Map<String, Object> parsed = gson.fromJson(credentialsJson, Map.class);
                    credentialsData = parsed;
                }
            }
            
            if (credentialsData == null) {
                // Try to use default credentials
                return GoogleCredentials.getApplicationDefault();
            }
            
            // Convert Map to JSON string for ServiceAccountCredentials
            com.google.gson.Gson gson = new com.google.gson.Gson();
            String json = gson.toJson(credentialsData);
            
            // Create credentials from service account info
            // In newer Google Auth library, fromStream may have different signature
            try {
                return ServiceAccountCredentials.fromStream(
                    new ByteArrayInputStream(json.getBytes())
                ).createScoped(
                    java.util.Collections.singletonList(
                        "https://www.googleapis.com/auth/cloud-platform.read-only")
                );
            } catch (IOException e) {
                throw new RuntimeException("Failed to create service account credentials", e);
            }
            
        } catch (IOException e) {
            throw new RuntimeException("Failed to create Google credentials: " + e.getMessage(), e);
        }
    }

    private static ChatModel buildOpenAiModel(
            CopilotConfig config,
            String modelName,
            boolean requireBaseUrl) {
        return buildOpenAiModel(config, modelName, requireBaseUrl, null);
    }

    private static ChatModel buildOpenAiModel(
            CopilotConfig config,
            String modelName,
            boolean requireBaseUrl,
            Integer maxTokens) {
        String baseUrl = getFirstStringParam(
            config,
            "base_url",
            "baseUrl",
            "api_base",
            "openai_api_base",
            "openai_base_url"
        );
        if (requireBaseUrl && (baseUrl == null || baseUrl.isBlank())) {
            throw new IllegalArgumentException(
                "Unsupported model provider: " + config.getModelProvider() + ". Missing base_url.");
        }
        OpenAiChatModel.OpenAiChatModelBuilder builder = OpenAiChatModel.builder()
            .apiKey(requireApiKey(config))
            .modelName(modelName)
            .temperature(getDoubleParam(config, 0.7, "temperature"))
            .timeout(getTimeoutParam(config, 30));
        Integer resolvedMaxTokens = maxTokens != null ? maxTokens : getIntParam(config, null, "max_tokens", "maxTokens");
        if (resolvedMaxTokens != null) {
            builder.maxTokens(resolvedMaxTokens);
        }
        if (baseUrl != null && !baseUrl.isBlank()) {
            builder.baseUrl(baseUrl);
        }
        applyOpenAiOptionalParams(builder, config);
        return builder.build();
    }

    private static StreamingChatModel buildOpenAiStreamingModel(
            CopilotConfig config,
            String modelName,
            boolean requireBaseUrl,
            Integer maxTokens) {
        String baseUrl = getFirstStringParam(
            config,
            "base_url",
            "baseUrl",
            "api_base",
            "openai_api_base",
            "openai_base_url"
        );
        if (requireBaseUrl && (baseUrl == null || baseUrl.isBlank())) {
            throw new IllegalArgumentException(
                "Unsupported model provider: " + config.getModelProvider() + ". Missing base_url.");
        }
        OpenAiStreamingChatModel.OpenAiStreamingChatModelBuilder builder = OpenAiStreamingChatModel.builder()
            .apiKey(requireApiKey(config))
            .modelName(modelName)
            .temperature(getDoubleParam(config, 0.7, "temperature"))
            .timeout(getTimeoutParam(config, 30));
        Integer resolvedMaxTokens = maxTokens != null ? maxTokens : getIntParam(config, null, "max_tokens", "maxTokens");
        if (resolvedMaxTokens != null) {
            builder.maxTokens(resolvedMaxTokens);
        }
        if (baseUrl != null && !baseUrl.isBlank()) {
            builder.baseUrl(baseUrl);
        }
        applyOpenAiOptionalParams(builder, config);
        return builder.build();
    }

    private static StreamingChatModel buildAnthropicStreamingModel(
            CopilotConfig config,
            String modelName,
            Integer maxTokens) {
        AnthropicStreamingChatModel.AnthropicStreamingChatModelBuilder builder = AnthropicStreamingChatModel.builder()
            .apiKey(requireApiKey(config))
            .modelName(modelName)
            .temperature(getDoubleParam(config, 0.7, "temperature"))
            .timeout(getTimeoutParam(config, 30));
        Integer resolvedMaxTokens = maxTokens != null ? maxTokens : getIntParam(config, 4096, "max_tokens", "maxTokens");
        if (resolvedMaxTokens != null) {
            builder.maxTokens(resolvedMaxTokens);
        }
        applyAnthropicOptionalParams(builder, config);
        return builder.build();
    }

    private static StreamingChatModel buildVertexStreamingModel(
            CopilotConfig config,
            String modelName,
            Integer maxTokens) {
        GoogleCredentials credentials = createGoogleCredentials(config);
        dev.langchain4j.model.vertexai.gemini.VertexAiGeminiStreamingChatModel.VertexAiGeminiStreamingChatModelBuilder builder =
            dev.langchain4j.model.vertexai.gemini.VertexAiGeminiStreamingChatModel.builder()
                .project(getStringParam(config, "project_id", "project"))
                .location(getStringParam(config, "location", "region", "us-central1"))
                .modelName(modelName)
                .temperature((float) getDoubleParam(config, 0.7, "temperature"));
        Integer resolvedMaxTokens = maxTokens != null ? maxTokens : getIntParam(config, 4096, "max_tokens", "maxTokens");
        if (resolvedMaxTokens != null) {
            builder.maxOutputTokens(resolvedMaxTokens);
        }
        if (credentials != null) {
            builder.credentials(credentials);
        }
        return builder.build();
    }

    private static ChatModel buildOpenAiCompatibleModel(
            CopilotConfig config,
            String modelName,
            boolean requireBaseUrl) {
        return buildOpenAiCompatibleModel(config, modelName, requireBaseUrl, null);
    }

    private static ChatModel buildOpenAiCompatibleModel(
            CopilotConfig config,
            String modelName,
            boolean requireBaseUrl,
            Integer maxTokens) {
        String baseUrl = getFirstStringParam(
            config,
            "base_url",
            "baseUrl",
            "api_base",
            "openai_api_base",
            "openai_base_url"
        );
        if (requireBaseUrl && (baseUrl == null || baseUrl.isBlank())) {
            throw new IllegalArgumentException(
                "Unsupported model provider: " + config.getModelProvider() + ". Missing base_url.");
        }
        return buildOpenAiModel(config, modelName, requireBaseUrl, maxTokens);
    }

    private static String getFirstStringParam(CopilotConfig config, String... keys) {
        for (String key : keys) {
            String value = getStringParam(config, key);
            if (value != null && !value.isBlank()) {
                return value;
            }
        }
        return null;
    }

    private static String requireApiKey(CopilotConfig config) {
        String apiKey = getStringParam(config, "api_key");
        if (apiKey == null || apiKey.isBlank()) {
            throw new IllegalArgumentException("Missing LLM API key in copilot additional_params (api_key)");
        }
        return apiKey;
    }

    private static String getStringParam(CopilotConfig config, String... keys) {
        for (String key : keys) {
            Object value = config.getAdditionalParams().get(key);
            if (value == null) {
                continue;
            }
            if (value instanceof String) {
                String str = (String) value;
                if (!str.isBlank()) {
                    return str;
                }
            } else {
                String str = String.valueOf(value);
                if (!str.isBlank()) {
                    return str;
                }
            }
        }
        return null;
    }

    private static List<String> getStringListParam(CopilotConfig config, String... keys) {
        Object value = getFirstParam(config, keys);
        if (value == null) {
            return null;
        }
        if (value instanceof List) {
            List<?> rawList = (List<?>) value;
            List<String> result = new ArrayList<>();
            for (Object item : rawList) {
                if (item != null) {
                    result.add(String.valueOf(item));
                }
            }
            return result.isEmpty() ? null : result;
        }
        if (value instanceof String) {
            String str = (String) value;
            if (!str.isBlank()) {
                List<String> result = new ArrayList<>();
                result.add(str);
                return result;
            }
        }
        return null;
    }

    private static Map<String, Integer> getIntMapParam(CopilotConfig config, String... keys) {
        Object value = getFirstParam(config, keys);
        if (!(value instanceof Map)) {
            return null;
        }
        Map<?, ?> raw = (Map<?, ?>) value;
        Map<String, Integer> converted = new HashMap<>();
        for (Map.Entry<?, ?> entry : raw.entrySet()) {
            if (entry.getKey() == null || entry.getValue() == null) {
                continue;
            }
            Integer mapped = null;
            Object rawValue = entry.getValue();
            if (rawValue instanceof Number) {
                mapped = ((Number) rawValue).intValue();
            } else if (rawValue instanceof String) {
                try {
                    mapped = Integer.parseInt((String) rawValue);
                } catch (NumberFormatException e) {
                    mapped = null;
                }
            }
            if (mapped != null) {
                converted.put(String.valueOf(entry.getKey()), mapped);
            }
        }
        return converted.isEmpty() ? null : converted;
    }

    private static double getDoubleParam(CopilotConfig config, double defaultValue, String... keys) {
        Object value = getFirstParam(config, keys);
        if (value instanceof Number) {
            return ((Number) value).doubleValue();
        }
        if (value instanceof String) {
            try {
                return Double.parseDouble((String) value);
            } catch (NumberFormatException e) {
                return defaultValue;
            }
        }
        return defaultValue;
    }

    private static Integer getIntParam(CopilotConfig config, Integer defaultValue, String... keys) {
        Object value = getFirstParam(config, keys);
        if (value instanceof Number) {
            return ((Number) value).intValue();
        }
        if (value instanceof String) {
            try {
                return Integer.parseInt((String) value);
            } catch (NumberFormatException e) {
                return defaultValue;
            }
        }
        return defaultValue;
    }

    private static Duration getTimeoutParam(CopilotConfig config, int defaultSeconds) {
        Integer seconds = getIntParam(config, defaultSeconds, "timeout", "timeout_seconds", "timeoutSeconds");
        return Duration.ofSeconds(seconds != null ? seconds : defaultSeconds);
    }

    private static Double getOptionalDoubleParam(CopilotConfig config, String... keys) {
        Object value = getFirstParam(config, keys);
        if (value instanceof Number) {
            return ((Number) value).doubleValue();
        }
        if (value instanceof String) {
            try {
                return Double.parseDouble((String) value);
            } catch (NumberFormatException e) {
                return null;
            }
        }
        return null;
    }

    private static Integer getOptionalIntParam(CopilotConfig config, String... keys) {
        Object value = getFirstParam(config, keys);
        if (value instanceof Number) {
            return ((Number) value).intValue();
        }
        if (value instanceof String) {
            try {
                return Integer.parseInt((String) value);
            } catch (NumberFormatException e) {
                return null;
            }
        }
        return null;
    }

    private static Object getFirstParam(CopilotConfig config, String... keys) {
        for (String key : keys) {
            if (config.getAdditionalParams().containsKey(key)) {
                return config.getAdditionalParams().get(key);
            }
        }
        return null;
    }

    private static void applyOpenAiOptionalParams(OpenAiChatModel.OpenAiChatModelBuilder builder, CopilotConfig config) {
        String organizationId = getStringParam(config, "organization_id", "organizationId");
        if (organizationId != null) {
            builder.organizationId(organizationId);
        }
        String projectId = getStringParam(config, "project_id", "projectId");
        if (projectId != null) {
            builder.projectId(projectId);
        }
        Double topP = getOptionalDoubleParam(config, "top_p", "topP");
        if (topP != null) {
            builder.topP(topP);
        }
        Double frequencyPenalty = getOptionalDoubleParam(config, "frequency_penalty", "frequencyPenalty");
        if (frequencyPenalty != null) {
            builder.frequencyPenalty(frequencyPenalty);
        }
        Double presencePenalty = getOptionalDoubleParam(config, "presence_penalty", "presencePenalty");
        if (presencePenalty != null) {
            builder.presencePenalty(presencePenalty);
        }
        Integer maxCompletionTokens = getOptionalIntParam(config, "max_completion_tokens", "maxCompletionTokens");
        if (maxCompletionTokens != null) {
            builder.maxCompletionTokens(maxCompletionTokens);
        }
        Integer seed = getOptionalIntParam(config, "seed");
        if (seed != null) {
            builder.seed(seed);
        }
        String user = getStringParam(config, "user");
        if (user != null) {
            builder.user(user);
        }
        String responseFormat = getStringParam(config, "response_format", "responseFormat");
        if (responseFormat != null) {
            builder.responseFormat(responseFormat);
        }
        List<String> stop = getStringListParam(config, "stop", "stop_sequences", "stopSequences");
        if (stop != null) {
            builder.stop(stop);
        }
        Map<String, Integer> logitBias = getIntMapParam(config, "logit_bias", "logitBias");
        if (logitBias != null) {
            builder.logitBias(logitBias);
        }
    }

    private static void applyOpenAiOptionalParams(OpenAiStreamingChatModel.OpenAiStreamingChatModelBuilder builder, CopilotConfig config) {
        String organizationId = getStringParam(config, "organization_id", "organizationId");
        if (organizationId != null) {
            builder.organizationId(organizationId);
        }
        String projectId = getStringParam(config, "project_id", "projectId");
        if (projectId != null) {
            builder.projectId(projectId);
        }
        Double topP = getOptionalDoubleParam(config, "top_p", "topP");
        if (topP != null) {
            builder.topP(topP);
        }
        Double frequencyPenalty = getOptionalDoubleParam(config, "frequency_penalty", "frequencyPenalty");
        if (frequencyPenalty != null) {
            builder.frequencyPenalty(frequencyPenalty);
        }
        Double presencePenalty = getOptionalDoubleParam(config, "presence_penalty", "presencePenalty");
        if (presencePenalty != null) {
            builder.presencePenalty(presencePenalty);
        }
        Integer maxCompletionTokens = getOptionalIntParam(config, "max_completion_tokens", "maxCompletionTokens");
        if (maxCompletionTokens != null) {
            builder.maxCompletionTokens(maxCompletionTokens);
        }
        Integer seed = getOptionalIntParam(config, "seed");
        if (seed != null) {
            builder.seed(seed);
        }
        String user = getStringParam(config, "user");
        if (user != null) {
            builder.user(user);
        }
        String responseFormat = getStringParam(config, "response_format", "responseFormat");
        if (responseFormat != null) {
            builder.responseFormat(responseFormat);
        }
        List<String> stop = getStringListParam(config, "stop", "stop_sequences", "stopSequences");
        if (stop != null) {
            builder.stop(stop);
        }
        Map<String, Integer> logitBias = getIntMapParam(config, "logit_bias", "logitBias");
        if (logitBias != null) {
            builder.logitBias(logitBias);
        }
    }

    private static void applyAnthropicOptionalParams(AnthropicChatModel.AnthropicChatModelBuilder builder, CopilotConfig config) {
        String baseUrl = getStringParam(config, "base_url", "baseUrl");
        if (baseUrl != null) {
            builder.baseUrl(baseUrl);
        }
        String version = getStringParam(config, "version");
        if (version != null) {
            builder.version(version);
        }
        String beta = getStringParam(config, "beta");
        if (beta != null) {
            builder.beta(beta);
        }
        Double topP = getOptionalDoubleParam(config, "top_p", "topP");
        if (topP != null) {
            builder.topP(topP);
        }
        Integer topK = getOptionalIntParam(config, "top_k", "topK");
        if (topK != null) {
            builder.topK(topK);
        }
        List<String> stopSequences = getStringListParam(config, "stop", "stop_sequences", "stopSequences");
        if (stopSequences != null) {
            builder.stopSequences(stopSequences);
        }
        String userId = getStringParam(config, "user_id", "userId");
        if (userId != null) {
            builder.userId(userId);
        }
        String thinkingType = getStringParam(config, "thinking_type", "thinkingType");
        if (thinkingType != null) {
            builder.thinkingType(thinkingType);
        }
        Integer thinkingBudgetTokens = getOptionalIntParam(config, "thinking_budget_tokens", "thinkingBudgetTokens");
        if (thinkingBudgetTokens != null) {
            builder.thinkingBudgetTokens(thinkingBudgetTokens);
        }
    }

    private static void applyAnthropicOptionalParams(AnthropicStreamingChatModel.AnthropicStreamingChatModelBuilder builder, CopilotConfig config) {
        String baseUrl = getStringParam(config, "base_url", "baseUrl");
        if (baseUrl != null) {
            builder.baseUrl(baseUrl);
        }
        String version = getStringParam(config, "version");
        if (version != null) {
            builder.version(version);
        }
        String beta = getStringParam(config, "beta");
        if (beta != null) {
            builder.beta(beta);
        }
        Double topP = getOptionalDoubleParam(config, "top_p", "topP");
        if (topP != null) {
            builder.topP(topP);
        }
        Integer topK = getOptionalIntParam(config, "top_k", "topK");
        if (topK != null) {
            builder.topK(topK);
        }
        List<String> stopSequences = getStringListParam(config, "stop", "stop_sequences", "stopSequences");
        if (stopSequences != null) {
            builder.stopSequences(stopSequences);
        }
        String userId = getStringParam(config, "user_id", "userId");
        if (userId != null) {
            builder.userId(userId);
        }
        String thinkingType = getStringParam(config, "thinking_type", "thinkingType");
        if (thinkingType != null) {
            builder.thinkingType(thinkingType);
        }
        Integer thinkingBudgetTokens = getOptionalIntParam(config, "thinking_budget_tokens", "thinkingBudgetTokens");
        if (thinkingBudgetTokens != null) {
            builder.thinkingBudgetTokens(thinkingBudgetTokens);
        }
    }

}

