package com.zenyard.ghidra.copilot;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.CompletableFuture;

import javax.swing.SwingUtilities;

import ghidra.app.services.CodeViewerService;
import ghidra.app.util.demangler.DemangledObject;
import ghidra.app.util.demangler.DemanglerUtil;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

import com.zenyard.ghidra.api.generated.ApiClient;
import com.zenyard.ghidra.api.generated.ApiException;
import com.zenyard.ghidra.api.generated.api.BinariesApi;
import com.zenyard.ghidra.api.generated.api.UserApi;
import com.zenyard.ghidra.copilot.tools.CopilotToolRegistry;
import com.zenyard.ghidra.copilot.tools.ToolUtils;
import com.zenyard.ghidra.copilot.tools.ToolExecutionListener;

import dev.langchain4j.data.message.AiMessage;
import dev.langchain4j.memory.ChatMemory;
import dev.langchain4j.model.chat.ChatModel;
import dev.langchain4j.model.output.Response;

/**
 * Manages conversation state, interacts with LangChain4j agent, and subscribes to program/decompiler context.
 * 
 * NOTE: mirrors functionality in zenyard_ida/copilot_task.py
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
    private ToolExecutionListener toolExecutionListener;
    
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
        this.toolExecutionListener = null;
    }
    
    /**
     * Set the view-model (optional, for better separation of concerns).
     */
    public void setViewModel(CopilotViewModel viewModel) {
        this.viewModel = viewModel;
        // Create stream handler with view model
        if (viewModel != null) {
            this.streamHandler = new CopilotStreamHandler(viewModel);
            this.toolExecutionListener = createToolExecutionListener(viewModel);
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
            // Create streaming chat model
            dev.langchain4j.model.chat.StreamingChatModel chatModel =
                CopilotAgent.createStreamingChatModel(copilotConfig);
            
            // Create streaming summarization model (separate LLM with maxTokens=10k)
            dev.langchain4j.model.chat.StreamingChatModel summarizationModel =
                CopilotAgent.createStreamingSummarizationModel(copilotConfig);
            
            // Get TokenCountEstimator from model (or use default based on provider)
            dev.langchain4j.model.TokenCountEstimator tokenCountEstimator = getTokenCountEstimator(null, copilotConfig);
            
            // Create memory with TokenCountEstimator
            memory = new CopilotMemory(COPILOT_THREAD_ID, tokenCountEstimator);
            ChatMemory chatMemory = memory.getChatMemory();
            
            // Create summarizer (also needs TokenCountEstimator)
            dev.langchain4j.model.TokenCountEstimator summarizationEstimator = getTokenCountEstimator(null, copilotConfig);
            summarizer = new CopilotSummarizer(summarizationModel, summarizationEstimator);
            
            // Create tools
            CopilotToolRegistry toolRegistry = new CopilotToolRegistry(
                currentProgram,
                TaskMonitor.DUMMY, // TODO: Use actual TaskMonitor if available
                tool,
                toolExecutionListener
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
        Msg.info(this, "Clearing conversation");
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
        if (viewModel != null) {
            viewModel.setThinking(false, null);
            viewModel.setLoading(false);
        }
    }

    /**
     * Hide the Copilot panel.
     */
    public void closePanel() {
        if (tool != null && provider != null) {
            tool.showComponentProvider(provider, false);
        }
    }

    /**
     * Search functions for autocomplete suggestions.
     */
    public void requestAutocomplete(String query, String requestId) {
        if (viewModel == null) {
            return;
        }
        if (currentProgram == null) {
            viewModel.setAutocomplete(Collections.emptyList(), requestId);
            return;
        }
        String trimmed = query != null ? query.trim() : "";
        if (trimmed.isEmpty()) {
            viewModel.setAutocomplete(Collections.emptyList(), requestId);
            return;
        }
        String needle = trimmed.toLowerCase();
        CompletableFuture.supplyAsync(() -> {
            final int limit = 20;
            List<CopilotViewModel.AutocompleteItem> prefixMatches = new ArrayList<>();
            List<CopilotViewModel.AutocompleteItem> containsMatches = new ArrayList<>();
            FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
            while (functions.hasNext()) {
                Function function = functions.next();
                String name = function.getName(true);
                if (name == null || name.isEmpty()) {
                    continue;
                }
                String nameLower = name.toLowerCase();
                boolean isPrefix = nameLower.startsWith(needle);
                boolean isContains = !isPrefix && nameLower.contains(needle);
                if (!isPrefix && !isContains) {
                    continue;
                }
                String address = ToolUtils.formatAddress(function.getEntryPoint());
                if (address == null) {
                    continue;
                }
                CopilotViewModel.AutocompleteItem item =
                    new CopilotViewModel.AutocompleteItem(name, address);
                if (isPrefix) {
                    prefixMatches.add(item);
                    if (prefixMatches.size() >= limit) {
                        break;
                    }
                } else if (containsMatches.size() < limit) {
                    containsMatches.add(item);
                }
                if (needle.length() >= 2
                        && (prefixMatches.size() + containsMatches.size()) >= limit) {
                    break;
                }
            }
            List<CopilotViewModel.AutocompleteItem> results =
                new ArrayList<>(prefixMatches);
            for (CopilotViewModel.AutocompleteItem item : containsMatches) {
                if (results.size() >= limit) {
                    break;
                }
                results.add(item);
            }
            return results;
        }).thenAccept(results -> viewModel.setAutocomplete(results, requestId))
            .exceptionally(throwable -> {
                Msg.debug(this, "Copilot autocomplete failed: " + throwable.getMessage());
                viewModel.setAutocomplete(Collections.emptyList(), requestId);
                return null;
            });
    }

    /**
     * Handle navigation requests from the UI (ghidra:// links).
     */
    public void navigateToLink(String url) {
        if (url == null || url.isEmpty()) {
            return;
        }
        if (currentProgram == null) {
            Msg.debug(this, "Copilot navigate: no program loaded");
            return;
        }
        try {
            URI uri = new URI(url);
            if (uri.getScheme() == null || !"ghidra".equalsIgnoreCase(uri.getScheme())) {
                Msg.debug(this, "Copilot navigate: unsupported scheme " + uri.getScheme());
                return;
            }

            String target = uri.getHost();
            String path = uri.getPath();
            String value = null;

            if (target == null || target.isEmpty()) {
                if (path == null || path.isEmpty()) {
                    Msg.debug(this, "Copilot navigate: missing target in " + url);
                    return;
                }
                String trimmed = path.startsWith("/") ? path.substring(1) : path;
                String[] parts = trimmed.split("/", 2);
                if (parts.length < 2) {
                    Msg.debug(this, "Copilot navigate: incomplete path in " + url);
                    return;
                }
                target = parts[0];
                value = parts[1];
            } else if (path != null && path.length() > 1) {
                value = path.substring(1);
            }

            if (value == null || value.isEmpty()) {
                Msg.debug(this, "Copilot navigate: empty target value in " + url);
                return;
            }
            String decodedValue = URLDecoder.decode(value, StandardCharsets.UTF_8);

            switch (target.toLowerCase()) {
                case "function":
                case "address":
                case "addr":
                    navigateToAddress(decodedValue);
                    break;
                case "symbol":
                case "name":
                    navigateToSymbol(decodedValue);
                    break;
                default:
                    Msg.debug(this, "Copilot navigate: unsupported target " + target);
                    break;
            }
        } catch (Exception e) {
            Msg.debug(this, "Copilot navigate failed: " + e.getMessage());
        }
    }

    private void navigateToAddress(String address) {
        Address addr = ToolUtils.parseAddress(currentProgram, address);
        if (addr == null) {
            Msg.debug(this, "Copilot navigate: invalid address " + address);
            return;
        }
        goToAddress(addr);
    }

    private void navigateToSymbol(String symbolName) {
        Address addr = resolveSymbolAddress(symbolName);
        if (addr == null) {
            Msg.debug(this, "Copilot navigate: symbol not found " + symbolName);
            return;
        }
        goToAddress(addr);
    }

    private void goToAddress(Address address) {
        if (tool == null) {
            Msg.debug(this, "Copilot navigate: tool unavailable");
            return;
        }
        CodeViewerService codeViewer = tool.getService(CodeViewerService.class);
        if (codeViewer == null) {
            Msg.debug(this, "Copilot navigate: code viewer service unavailable");
            return;
        }
        Runnable action = () -> {
            ProgramLocation location = new ProgramLocation(currentProgram, address);
            codeViewer.goTo(location, false);
        };
        if (SwingUtilities.isEventDispatchThread()) {
            action.run();
        } else {
            SwingUtilities.invokeLater(action);
        }
    }

    private Address resolveSymbolAddress(String symbolName) {
        if (symbolName == null || symbolName.isEmpty()) {
            return null;
        }
        SymbolTable symbolTable = currentProgram.getSymbolTable();
        Iterator<Symbol> symbolsIter = symbolTable.getSymbols(symbolName);
        if (symbolsIter.hasNext()) {
            return symbolsIter.next().getAddress();
        }
        Symbol demangledMatch = resolveByDemangledName(symbolTable, symbolName);
        return demangledMatch != null ? demangledMatch.getAddress() : null;
    }

    private Symbol resolveByDemangledName(SymbolTable symbolTable, String symbolName) {
        String normalizedInput = DemanglerUtil.stripSuperfluousSignatureSpaces(symbolName);
        SymbolIterator iter = symbolTable.getDefinedSymbols();
        while (iter.hasNext()) {
            Symbol symbol = iter.next();
            String name = symbol.getName();
            Address address = symbol.getAddress();
            List<DemangledObject> demangledList = DemanglerUtil.demangle(currentProgram, name, address);
            if (demangledList == null || demangledList.isEmpty()) {
                continue;
            }
            DemangledObject demangled = demangledList.get(0);
            String demangledName = demangled.getDemangledName();
            String signature = demangled.getSignature();
            if (demangledName != null && (symbolName.equals(demangledName)
                    || normalizedInput.equals(DemanglerUtil.stripSuperfluousSignatureSpaces(demangledName)))) {
                return symbol;
            }
            if (signature != null && (symbolName.equals(signature)
                    || normalizedInput.equals(DemanglerUtil.stripSuperfluousSignatureSpaces(signature)))) {
                return symbol;
            }
        }
        return null;
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
            viewModel.setThinking(true, "Thinking...");
            // Add empty AI message for streaming
            viewModel.addMessage("", false);
        } else {
            // Update UI on EDT
            SwingUtilities.invokeLater(() -> {
                provider.appendMessage("You: " + message);
                provider.appendMessage("Zenyard: Thinking...");
            });
        }
        
        // Ensure agent is initialized
        if (agent == null) {
            if (copilotConfig == null) {
                handleError("Copilot settings not configured. Please configure Copilot settings.", null);
                return;
            }
            if (currentProgram == null) {
                handleError("No program loaded. Please open a program to use Copilot.", null);
                return;
            }
            initializeAgent();
            if (agent == null) {
                handleError("Copilot agent failed to initialize. Please check logs.", null);
                return;
            }
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
                    viewModel.setThinking(false, null);
                    // If streaming isn't supported, append response to last message
                    List<CopilotViewModel.Message> messages = viewModel.getMessages();
                    if (!messages.isEmpty()) {
                        CopilotViewModel.Message last = messages.get(messages.size() - 1);
                        if (!last.isFromUser() && (last.getText() == null || last.getText().isEmpty())) {
                            viewModel.appendToLastMessage(response);
                        }
                    }
                } else {
                    provider.appendMessage("Zenyard: " + response);
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
                viewModel.setThinking(false, null);
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

    private ToolExecutionListener createToolExecutionListener(CopilotViewModel model) {
        return new ToolExecutionListener() {
            @Override
            public void onToolStart(String toolName, java.util.Map<String, Object> arguments) {
                SwingUtilities.invokeLater(() -> model.setThinking(true, "Running " + toolName + "..."));
            }

            @Override
            public void onToolSuccess(String toolName, long durationMs) {
                SwingUtilities.invokeLater(() -> model.setThinking(false, null));
            }

            @Override
            public void onToolError(String toolName, Throwable error, long durationMs) {
                SwingUtilities.invokeLater(() -> model.setThinking(false, null));
            }
        };
    }
}

