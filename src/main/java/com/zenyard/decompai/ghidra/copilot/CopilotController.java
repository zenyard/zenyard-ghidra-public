package com.zenyard.decompai.ghidra.copilot;

import java.util.List;
import java.util.concurrent.CompletableFuture;

import javax.swing.SwingUtilities;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

import com.zenyard.decompai.ghidra.api.generated.ApiClient;
import com.zenyard.decompai.ghidra.api.generated.ApiException;
import com.zenyard.decompai.ghidra.api.generated.api.BinariesApi;
import com.zenyard.decompai.ghidra.api.generated.api.UserApi;
import com.zenyard.decompai.ghidra.copilot.tools.CopilotToolRegistry;

import dev.langchain4j.data.message.AiMessage;
import dev.langchain4j.memory.ChatMemory;
import dev.langchain4j.model.chat.ChatModel;
import dev.langchain4j.model.output.Response;

/**
 * Manages conversation state, interacts with LangChain4j agent, and subscribes to program/decompiler context.
 * 
 * NOTE: mirrors functionality in decompai_ida/copilot_task.py
 * 
 * All UI updates are performed on the Event Dispatch Thread (EDT) using SwingUtilities.invokeLater().
 * 
 * Optionally uses CopilotViewModel for better separation of concerns.
 */
public class CopilotController {
    
    private static final String COPILOT_THREAD_ID = "1"; // Matches IDA's COPILOT_THREAD_ID
    
    private final CopilotProvider provider;
    private final PluginTool tool;
    private CopilotViewModel viewModel; // Optional view-model
    private Program currentProgram;
    
    private CopilotAgent agent;
    private CopilotMemory memory;
    private CopilotStreamHandler streamHandler;
    private CopilotConfig copilotConfig;
    private CopilotSummarizer summarizer;
    
    public CopilotController(CopilotProvider provider, ApiClient apiClient, BinariesApi binariesApi, UserApi userApi, PluginTool tool) {
        this.provider = provider;
        // Note: apiClient, binariesApi, userApi parameters kept for API compatibility but not stored
        this.tool = tool;
        this.viewModel = null; // Optional - can be set later
        this.currentProgram = null;
        this.agent = null;
        this.memory = null;
        this.streamHandler = null;
        this.copilotConfig = null;
    }
    
    /**
     * Set the view-model (optional, for better separation of concerns).
     */
    public void setViewModel(CopilotViewModel viewModel) {
        this.viewModel = viewModel;
        // Create stream handler with view model
        if (viewModel != null) {
            this.streamHandler = new CopilotStreamHandler(viewModel);
        }
    }
    
    public void setCurrentProgram(Program program) {
        this.currentProgram = program;
        // Reinitialize agent if needed when program changes
        if (copilotConfig != null && program != null) {
            initializeAgent();
        }
    }
    
    /**
     * Set copilot configuration and initialize agent.
     */
    public void setCopilotConfig(CopilotConfig config) {
        this.copilotConfig = config;
        if (currentProgram != null) {
            initializeAgent();
        }
    }
    
    /**
     * Initialize the LangChain4j agent with tools and memory.
     */
    private void initializeAgent() {
        if (copilotConfig == null || currentProgram == null) {
            return;
        }
        
        try {
            // Create chat model
            ChatModel chatModel = CopilotAgent.createChatModel(copilotConfig);
            
            // Create summarization model (separate LLM with maxTokens=10k)
            ChatModel summarizationModel = CopilotAgent.createSummarizationModel(copilotConfig);
            
            // Get TokenCountEstimator from model (or use default based on provider)
            dev.langchain4j.model.TokenCountEstimator tokenCountEstimator = getTokenCountEstimator(chatModel, copilotConfig);
            
            // Create memory with TokenCountEstimator
            memory = new CopilotMemory(COPILOT_THREAD_ID, tokenCountEstimator);
            ChatMemory chatMemory = memory.getChatMemory();
            
            // Create summarizer (also needs TokenCountEstimator)
            dev.langchain4j.model.TokenCountEstimator summarizationEstimator = getTokenCountEstimator(summarizationModel, copilotConfig);
            summarizer = new CopilotSummarizer(summarizationModel, summarizationEstimator);
            
            // Create tools
            CopilotToolRegistry toolRegistry = new CopilotToolRegistry(
                currentProgram,
                TaskMonitor.DUMMY, // TODO: Use actual TaskMonitor if available
                tool
            );
            List<Object> tools = toolRegistry.getAllTools();
            
            // Create agent
            agent = new CopilotAgent(chatModel, chatMemory, tools, streamHandler);
            
            // Set summarizer and memory on agent
            agent.setSummarizer(summarizer, memory);
        } catch (Exception e) {
            Msg.showError(this, null, "Copilot Initialization Error",
                "Failed to initialize Copilot agent: " + e.getMessage(), e);
        }
    }
    
    /**
     * Clear the conversation.
     */
    public void clearConversation() {
        if (memory != null) {
            memory.clear();
        }
        if (viewModel != null) {
            viewModel.clearMessages();
        }
    }
    
    /**
     * Stop the current agent operation.
     */
    public void stop() {
        if (streamHandler != null) {
            streamHandler.cancel();
        }
    }
    
    /**
     * Get TokenCountEstimator for the chat model.
     * Uses model-specific estimator if available, otherwise creates one based on provider.
     */
    private dev.langchain4j.model.TokenCountEstimator getTokenCountEstimator(
            ChatModel chatModel, CopilotConfig config) {
        String provider = config.getModelProvider();
        String modelName = config.getModelName();
        
        try {
            switch (provider) {
                case "openai":
                    return new dev.langchain4j.model.openai.OpenAiTokenCountEstimator(modelName);
                case "anthropic":
                    // AnthropicTokenCountEstimator requires API key and model name
                    // Use OpenAI as fallback for Anthropic since it requires API calls
                    return new dev.langchain4j.model.openai.OpenAiTokenCountEstimator("gpt-4");
                case "google_vertex_ai":
                case "google_anthropic_vertex":
                    // Use OpenAI estimator as fallback for Vertex AI
                    return new dev.langchain4j.model.openai.OpenAiTokenCountEstimator("gpt-4");
                default:
                    // Use OpenAI estimator as fallback
                    return new dev.langchain4j.model.openai.OpenAiTokenCountEstimator("gpt-4");
            }
        } catch (Exception e) {
            // If specific estimators fail, use OpenAI as fallback
            try {
                return new dev.langchain4j.model.openai.OpenAiTokenCountEstimator("gpt-4");
            } catch (Exception e2) {
                // Last resort: return a simple estimator that counts characters
                return new dev.langchain4j.model.TokenCountEstimator() {
                    @Override
                    public int estimateTokenCountInText(String text) {
                        return text.length() / 4; // Rough estimate: 4 chars per token
                    }
                    
                    @Override
                    public int estimateTokenCountInMessage(dev.langchain4j.data.message.ChatMessage message) {
                        String text = extractTextFromMessage(message);
                        return estimateTokenCountInText(text != null ? text : "");
                    }
                    
                    @Override
                    public int estimateTokenCountInMessages(Iterable<dev.langchain4j.data.message.ChatMessage> messages) {
                        int total = 0;
                        for (dev.langchain4j.data.message.ChatMessage message : messages) {
                            total += estimateTokenCountInMessage(message);
                        }
                        return total;
                    }
                    
                    private String extractTextFromMessage(dev.langchain4j.data.message.ChatMessage message) {
                        if (message instanceof dev.langchain4j.data.message.UserMessage) {
                            return ((dev.langchain4j.data.message.UserMessage) message).singleText();
                        } else if (message instanceof dev.langchain4j.data.message.AiMessage) {
                            return ((dev.langchain4j.data.message.AiMessage) message).text();
                        } else if (message instanceof dev.langchain4j.data.message.SystemMessage) {
                            return ((dev.langchain4j.data.message.SystemMessage) message).text();
                        }
                        return message.toString();
                    }
                };
            }
        }
    }
    
    public void sendMessage(String message) {
        // Use view-model if available, otherwise update provider directly
        if (viewModel != null) {
            viewModel.addMessage(message, true);
            viewModel.setLoading(true);
            // Add empty AI message for streaming
            viewModel.addMessage("", false);
        } else {
            // Update UI on EDT
            SwingUtilities.invokeLater(() -> {
                provider.appendMessage("You: " + message);
                provider.appendMessage("DecompAI: Thinking...");
            });
        }
        
        // Check if agent is initialized
        if (agent == null) {
            String errorMsg = "Copilot agent not initialized. Please configure Copilot settings.";
            handleError(errorMsg, null);
            return;
        }
        
        // Send message to agent asynchronously
        CompletableFuture.supplyAsync(() -> {
            try {
                Response<AiMessage> response = agent.chat(message);
                return response.content().text();
            } catch (Exception e) {
                throw new RuntimeException("Error during agent chat: " + e.getMessage(), e);
            }
        }).thenAccept(response -> {
            // Use view-model if available, otherwise update provider directly
            SwingUtilities.invokeLater(() -> {
                if (viewModel != null) {
                    viewModel.setLoading(false);
                    // Response already added via streaming handler
                } else {
                    provider.appendMessage("DecompAI: " + response);
                }
            });
        }).exceptionally(throwable -> {
            handleError("Error: " + throwable.getMessage(), throwable);
            return null;
        });
    }
    
    private void handleError(String errorMsg, Throwable throwable) {
        if (throwable != null && throwable.getCause() instanceof ApiException) {
            errorMsg = "API Error: " + throwable.getCause().getMessage();
        }
        final String finalErrorMsg = errorMsg;
        
        // Use view-model if available, otherwise update provider directly
        SwingUtilities.invokeLater(() -> {
            if (viewModel != null) {
                viewModel.setLoading(false);
                viewModel.setError(finalErrorMsg);
                viewModel.addMessage(finalErrorMsg, false);
            } else {
                provider.appendMessage(finalErrorMsg);
                if (throwable != null) {
                    Msg.showError(this, null, "Copilot Error", finalErrorMsg, throwable);
                }
            }
        });
    }
}

