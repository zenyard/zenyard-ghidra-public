package com.zenyard.decompai.ghidra.copilot;

import java.time.Duration;
import java.util.List;

import dev.langchain4j.data.message.AiMessage;
import dev.langchain4j.data.message.SystemMessage;
import dev.langchain4j.data.message.UserMessage;
import dev.langchain4j.memory.ChatMemory;
import dev.langchain4j.model.chat.ChatModel;
import dev.langchain4j.model.chat.StreamingChatModel;
import dev.langchain4j.model.chat.request.ChatRequest;
import dev.langchain4j.model.openai.OpenAiChatModel;
import dev.langchain4j.model.anthropic.AnthropicChatModel;
import dev.langchain4j.model.output.Response;
import dev.langchain4j.service.AiServices;

import com.google.auth.oauth2.ServiceAccountCredentials;
import com.google.auth.oauth2.GoogleCredentials;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Map;

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
        Response<AiMessage> chat(String message);
    }
    
    private final CopilotAgentService agent;
    private final ChatModel chatModel;
    private final ChatMemory chatMemory;
    private final CopilotStreamHandler streamHandler;
    private CopilotSummarizer summarizer; // Optional summarizer
    private CopilotMemory copilotMemory; // Reference to CopilotMemory for summarization
    
    public CopilotAgent(
            ChatModel chatModel,
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
            .chatModel(chatModel)
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
            
            // Add user message to memory
            chatMemory.add(UserMessage.userMessage(message));
            
            // Check if summarization is needed after adding user message
            if (summarizer != null && copilotMemory != null) {
                summarizer.summarizeIfNeeded(copilotMemory);
            }
            
            // Use streaming if streamHandler is provided and chatModel supports streaming
            if (streamHandler != null && chatModel instanceof StreamingChatModel) {
                StreamingChatModel streamingModel = (StreamingChatModel) chatModel;
                
                // Build chat request with messages from memory
                ChatRequest chatRequest = ChatRequest.builder()
                    .messages(chatMemory.messages())
                    .build();
                
                // Create a handler that updates memory and returns response
                final Response<AiMessage>[] responseHolder = new Response[1];
                final Exception[] errorHolder = new Exception[1];
                
                dev.langchain4j.model.chat.response.StreamingChatResponseHandler handler = 
                    new dev.langchain4j.model.chat.response.StreamingChatResponseHandler() {
                    @Override
                    public void onPartialResponse(String partialResponse) {
                        streamHandler.onPartialResponse(partialResponse);
                    }
                    
                    @Override
                    public void onCompleteResponse(dev.langchain4j.model.chat.response.ChatResponse completeResponse) {
                        // Update memory with AI message
                        chatMemory.add(completeResponse.aiMessage());
                        
                        // Convert ChatResponse to Response<AiMessage>
                        responseHolder[0] = Response.from(
                            completeResponse.aiMessage(),
                            completeResponse.metadata() != null ? completeResponse.metadata().tokenUsage() : null,
                            completeResponse.metadata() != null ? completeResponse.metadata().finishReason() : null
                        );
                        
                        streamHandler.onCompleteResponse(completeResponse);
                    }
                    
                    @Override
                    public void onError(Throwable error) {
                        errorHolder[0] = error instanceof Exception ? (Exception) error : new RuntimeException(error);
                        streamHandler.onError(error);
                    }
                };
                
                // Call streaming model
                streamingModel.chat(chatRequest, handler);
                
                // Wait for completion (streaming is async)
                // In a real implementation, this should be handled asynchronously
                // For now, we'll wait a bit and check for response
                try {
                    Thread.sleep(100); // Give streaming a moment to start
                    int waitCount = 0;
                    while (responseHolder[0] == null && errorHolder[0] == null && waitCount < 1000) {
                        Thread.sleep(10);
                        waitCount++;
                    }
                    
                    if (errorHolder[0] != null) {
                        throw errorHolder[0];
                    }
                    
                    if (responseHolder[0] != null) {
                        // Check if summarization is needed after AI response
                        if (summarizer != null && copilotMemory != null) {
                            summarizer.summarizeIfNeeded(copilotMemory);
                        }
                        return responseHolder[0];
                    }
                    
                    // If we get here, streaming didn't complete in time
                    throw new RuntimeException("Streaming response did not complete in time");
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new RuntimeException("Streaming interrupted", e);
                }
            } else {
                // Non-streaming path
                Response<AiMessage> response = agent.chat(message);
                // Memory is already updated by AI Service
                
                // Check if summarization is needed after AI response
                if (summarizer != null && copilotMemory != null) {
                    summarizer.summarizeIfNeeded(copilotMemory);
                }
                
                return response;
            }
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
                baseModel = OpenAiChatModel.builder()
                    .apiKey(config.getAdditionalParam("api_key", String.class))
                    .modelName(modelName)
                    .temperature(config.getAdditionalParam("temperature", Double.class, 0.7))
                    .timeout(Duration.ofSeconds(30))
                    .build();
                break;
            
            case "anthropic":
                // AnthropicChatModel implements ChatModel in langchain4j 1.10.0
                baseModel = (ChatModel) AnthropicChatModel.builder()
                    .apiKey(config.getAdditionalParam("api_key", String.class))
                    .modelName(modelName)
                    .temperature(config.getAdditionalParam("temperature", Double.class, 0.7))
                    .maxTokens(config.getAdditionalParam("max_tokens", Integer.class, 4096))
                    .timeout(Duration.ofSeconds(30))
                    .build();
                break;
            
            case "google_vertex_ai":
            case "google_anthropic_vertex":
                // Handle service account credentials (like IDA implementation)
                GoogleCredentials credentials = createGoogleCredentials(config);
                
                dev.langchain4j.model.vertexai.gemini.VertexAiGeminiChatModel.VertexAiGeminiChatModelBuilder builder = 
                    dev.langchain4j.model.vertexai.gemini.VertexAiGeminiChatModel.builder()
                    .project(config.getAdditionalParam("project_id", String.class))
                    .location(config.getAdditionalParam("location", String.class, "us-central1"))
                    .modelName(modelName)
                    .temperature(config.getAdditionalParam("temperature", Double.class, 0.7).floatValue())
                    .maxOutputTokens(config.getAdditionalParam("max_tokens", Integer.class, 4096));
                
                if (credentials != null) {
                    builder.credentials(credentials);
                }
                
                baseModel = builder.build();
                break;
            
            default:
                throw new IllegalArgumentException("Unsupported model provider: " + provider);
        }
        
        // Wrap with rate limiter
        return new RateLimitedChatModel(baseModel, RATE_LIMITER);
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
                baseModel = OpenAiChatModel.builder()
                    .apiKey(config.getAdditionalParam("api_key", String.class))
                    .modelName(modelName)
                    .temperature(config.getAdditionalParam("temperature", Double.class, 0.7))
                    .maxTokens(10_000) // Summarization max tokens (matches IDA)
                    .timeout(Duration.ofSeconds(30))
                    .build();
                break;
            
            case "anthropic":
                // AnthropicChatModel implements ChatModel in langchain4j 1.10.0
                baseModel = (ChatModel) AnthropicChatModel.builder()
                    .apiKey(config.getAdditionalParam("api_key", String.class))
                    .modelName(modelName)
                    .temperature(config.getAdditionalParam("temperature", Double.class, 0.7))
                    .maxTokens(10_000) // Summarization max tokens (matches IDA)
                    .timeout(Duration.ofSeconds(30))
                    .build();
                break;
            
            case "google_vertex_ai":
            case "google_anthropic_vertex":
                // Handle service account credentials (like IDA implementation)
                GoogleCredentials credentials = createGoogleCredentials(config);
                
                dev.langchain4j.model.vertexai.gemini.VertexAiGeminiChatModel.VertexAiGeminiChatModelBuilder builder = 
                    dev.langchain4j.model.vertexai.gemini.VertexAiGeminiChatModel.builder()
                    .project(config.getAdditionalParam("project_id", String.class))
                    .location(config.getAdditionalParam("location", String.class, "us-central1"))
                    .modelName(modelName)
                    .temperature(config.getAdditionalParam("temperature", Double.class, 0.7).floatValue())
                    .maxOutputTokens(10_000); // Summarization max tokens (matches IDA)
                
                if (credentials != null) {
                    builder.credentials(credentials);
                }
                
                baseModel = builder.build();
                break;
            
            default:
                throw new IllegalArgumentException("Unsupported model provider: " + provider);
        }
        
        // Wrap with rate limiter (same rate limiter as main model)
        return new RateLimitedChatModel(baseModel, RATE_LIMITER);
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
}

