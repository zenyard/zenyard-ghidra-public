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

import com.zenyard.ghidra.api.generated.ApiClient;
import com.zenyard.ghidra.api.generated.ApiException;
import com.zenyard.ghidra.api.generated.api.BinariesApi;
import com.zenyard.ghidra.api.generated.api.UserApi;
import com.zenyard.ghidra.copilot.deepagent.CopilotDeepAgent;
import com.zenyard.ghidra.copilot.deepagent.CopilotDeepAgentConfig;
import com.zenyard.ghidra.copilot.deepagent.CopilotDeepState;
import com.zenyard.ghidra.copilot.deepagent.DeepAgentMemoryAdapter;
import com.zenyard.ghidra.copilot.deepagent.LangSmithTracer;
import com.zenyard.ghidra.copilot.storage.CopilotArtifactStorage;
import com.zenyard.ghidra.copilot.tools.CopilotToolRegistry;
import com.zenyard.ghidra.copilot.tools.RunPythonScriptTool;
import com.zenyard.ghidra.config.PluginConfiguration;
import com.zenyard.ghidra.config.ZenyardConfigFile;
import com.zenyard.ghidra.copilot.tools.ToolUtils;
import com.zenyard.ghidra.copilot.tools.ToolExecutionListener;
import com.zenyard.ghidra.ZenyardService;
import com.zenyard.ghidra.usage.UsageState;
import org.bsc.langgraph4j.NodeOutput;

import dev.langchain4j.exception.AuthenticationException;
import dev.langchain4j.memory.ChatMemory;
import dev.langchain4j.model.chat.ChatModel;

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
    private static final String PYTHON_UNAVAILABLE_WARNING_MESSAGE =
        "Python runtime is unavailable. Start Ghidra via pyghidraRun to enable the Python tool for better Copilot results.";
    
    private final CopilotProvider provider;
    private final PluginTool tool;
    private CopilotViewModel viewModel; // Optional view-model
    private Program currentProgram;
    
    private CopilotDeepAgent deepAgent;
    private DeepAgentMemoryAdapter deepAgentMemoryAdapter;
    private CopilotAgent agent;
    private CopilotMemory memory;
    private CopilotStreamHandler streamHandler;
    private CopilotConfig copilotConfig;
    private CopilotSummarizer summarizer;
    private ToolExecutionListener toolExecutionListener;
    private CopilotArtifactStorage artifactStorage;
    private int toolCount;
    private int subAgentCount;
    private String lastObservedActiveTodo;
    private long lastObservedActiveTodoSinceMs;
    private String lastObservedToolBatchSignature;
    private volatile long currentRunSendStartNs;
    private volatile long currentRunLastTodoDoneNs;
    private String persistedSessionNotes;
    private CopilotCancellationMonitor cancellationMonitor;
    private volatile CompletableFuture<?> currentRunFuture;
    
    public CopilotController(CopilotProvider provider, ApiClient apiClient, BinariesApi binariesApi, UserApi userApi, PluginTool tool) {
        this.provider = provider;
        // Note: apiClient, binariesApi, userApi parameters kept for API compatibility but not stored
        this.tool = tool;
        this.viewModel = null; // Optional - can be set later
        this.currentProgram = null;
        this.deepAgent = null;
        this.deepAgentMemoryAdapter = null;
        this.agent = null;
        this.memory = null;
        this.streamHandler = null;
        this.copilotConfig = null;
        this.toolExecutionListener = null;
        this.artifactStorage = null;
        this.toolCount = 0;
        this.subAgentCount = 0;
        this.lastObservedActiveTodo = "";
        this.lastObservedActiveTodoSinceMs = 0L;
        this.lastObservedToolBatchSignature = "";
        this.currentRunSendStartNs = 0L;
        this.currentRunLastTodoDoneNs = 0L;
        this.persistedSessionNotes = "";
    }

    private static final class DeepAgentRunResult {
        private final String response;
        private final long finalStateNs;
        private final long finalTextNs;
        private final boolean usedFallback;
        private final boolean usedStreamBuffer;
        private final int streamBufferChars;
        private final List<String> completedTodos;

        private DeepAgentRunResult(
                String response,
                long finalStateNs,
                long finalTextNs,
                boolean usedFallback,
                boolean usedStreamBuffer,
                int streamBufferChars,
                List<String> completedTodos) {
            this.response = response;
            this.finalStateNs = finalStateNs;
            this.finalTextNs = finalTextNs;
            this.usedFallback = usedFallback;
            this.usedStreamBuffer = usedStreamBuffer;
            this.streamBufferChars = streamBufferChars;
            this.completedTodos = completedTodos != null ? completedTodos : List.of();
        }
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
            boolean incrementalStream = getBooleanParam(
                copilotConfig, false, "deepagent_ui_incremental_stream", "deepAgentUiIncrementalStream");
            viewModel.setStreamDeltaEnabled(incrementalStream);
        }
        refreshPythonAvailabilityWarning();
    }
    
    public void setCurrentProgram(Program program) {
        this.currentProgram = program;
        // Reinitialize agent if needed when program changes
        if (copilotConfig != null && program != null) {
            initializeAgent();
        }
        refreshPythonAvailabilityWarning();
    }
    
    /**
     * Set copilot configuration and initialize agent.
     */
    public void setCopilotConfig(CopilotConfig config) {
        this.copilotConfig = config;
        if (viewModel != null) {
            boolean incrementalStream = getBooleanParam(
                config, false, "deepagent_ui_incremental_stream", "deepAgentUiIncrementalStream");
            viewModel.setStreamDeltaEnabled(incrementalStream);
        }
        refreshPythonAvailabilityWarning();
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
        refreshPythonAvailabilityWarning();
        
        try {
            // Create planning and streaming chat models
            dev.langchain4j.model.chat.ChatModel planningModel =
                CopilotAgent.createChatModel(copilotConfig);
            dev.langchain4j.model.chat.StreamingChatModel streamingModel =
                CopilotAgent.createStreamingChatModel(copilotConfig);
            
            // Create streaming summarization model (separate LLM with maxTokens=10k)
            dev.langchain4j.model.chat.StreamingChatModel summarizationModel =
                CopilotAgent.createStreamingSummarizationModel(copilotConfig);
            
            // Get TokenCountEstimator from model (or use default based on provider).
            // Preserve existing conversation memory across agent re-initialization.
            if (memory == null) {
                dev.langchain4j.model.TokenCountEstimator tokenCountEstimator =
                    getTokenCountEstimator(null, copilotConfig);
                memory = new CopilotMemory(COPILOT_THREAD_ID, tokenCountEstimator);
            }
            if (deepAgentMemoryAdapter == null) {
                ChatMemory chatMemory = memory.getChatMemory();
                deepAgentMemoryAdapter = new DeepAgentMemoryAdapter(chatMemory);
            }
            
            // Create summarizer (also needs TokenCountEstimator)
            dev.langchain4j.model.TokenCountEstimator summarizationEstimator = getTokenCountEstimator(null, copilotConfig);
            summarizer = new CopilotSummarizer(summarizationModel, summarizationEstimator);
            
            artifactStorage = new CopilotArtifactStorage(currentProgram);

            // Load session notes from previous runs and build a context-enriched system prompt
            persistedSessionNotes = artifactStorage.loadSessionSummary();
            String systemPrompt = persistedSessionNotes.isBlank()
                ? CopilotPrompts.SYSTEM_PROMPT
                : CopilotPrompts.SYSTEM_PROMPT + "\n\n" + CopilotPrompts.sessionNotesSection(persistedSessionNotes);

            CopilotDeepAgentConfig deepAgentConfig = buildDeepAgentConfig(copilotConfig);

            LangSmithTracer langSmithTracer = createLangSmithTracer();

            // Create cancellation monitor for this agent instance
            cancellationMonitor = new CopilotCancellationMonitor();

            // Create tools with cancellation-aware monitor
            CopilotToolRegistry toolRegistry = new CopilotToolRegistry(
                currentProgram,
                cancellationMonitor,
                tool,
                toolExecutionListener,
                artifactStorage,
                CopilotAgent.createSubAgentStreamingChatModel(copilotConfig),
                systemPrompt,
                deepAgentConfig.subAgentTimeoutMs(),
                deepAgentConfig.subAgentRecursionLimit(),
                langSmithTracer,
                createSubAgentProgressListener(),
                cancellationMonitor.asCancelledSupplier()
            );
            List<Object> tools = toolRegistry.getAllTools();
            refreshPythonAvailabilityWarning(tools);
            
            // Create deep agent graphs
            deepAgent = new CopilotDeepAgent(
                planningModel,
                streamingModel,
                tools,
                streamHandler,
                deepAgentMemoryAdapter,
                null,
                systemPrompt,
                shouldSanitizeToolMessages(copilotConfig),
                deepAgentConfig,
                langSmithTracer
            );
        } catch (Exception e) {
            Msg.showError(this, null, "Copilot Initialization Error",
                "Failed to initialize Copilot agent: " + e.getMessage(), e);
        }
    }

    private static LangSmithTracer createLangSmithTracer() {
        try {
            PluginConfiguration pluginConfig = ZenyardConfigFile.readConfiguration();
            String apiKey = pluginConfig.getLangsmithApiKey();
            if (apiKey == null || apiKey.isBlank()) {
                return new LangSmithTracer();
            }
            return new LangSmithTracer(
                    apiKey,
                    pluginConfig.getLangsmithEndpoint(),
                    pluginConfig.getLangsmithProject());
        } catch (Exception e) {
            Msg.debug(CopilotController.class,
                    "LangSmith tracer: config not available, tracing disabled");
            return new LangSmithTracer();
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
        if (deepAgentMemoryAdapter != null) {
            deepAgentMemoryAdapter.clear();
        }
        if (viewModel != null) {
            viewModel.clearMessages();
            viewModel.clearTodos();
            viewModel.clearToolHistory();
            viewModel.clearSubAgentStreaming();
        }
        lastObservedToolBatchSignature = "";
    }
    
    /**
     * Stop the current agent operation.
     * Cancels all layers: the cancellation monitor (propagates to tools and subagents),
     * the stream handler (stops UI token forwarding), and the running future.
     */
    public void stop() {
        if (cancellationMonitor != null) {
            cancellationMonitor.cancel();
        }
        if (streamHandler != null) {
            streamHandler.cancel();
        }
        CompletableFuture<?> runFuture = currentRunFuture;
        if (runFuture != null) {
            runFuture.cancel(true);
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
        ZenyardService services = ZenyardService.getInstance();
        if (services != null) {
            if (!services.isServerConnected()) {
                return;
            }
            UsageState usageState = services.getUsageState();
            if (usageState != null && usageState.isBlocked()) {
                return;
            }
        }
        currentRunSendStartNs = System.nanoTime();
        currentRunLastTodoDoneNs = 0L;
        lastObservedToolBatchSignature = "";
        if (cancellationMonitor != null) {
            cancellationMonitor.clearCancelled();
        }
        if (streamHandler != null) {
            streamHandler.reset();
        }
        // Use view-model if available, otherwise update provider directly
        if (viewModel != null) {
            // Reset task-progress state at the start of every prompt so each run starts fresh.
            viewModel.syncTodoState(
                Collections.emptyList(),
                null,
                Collections.emptyList(),
                Collections.emptyList()
            );
            viewModel.clearToolHistory();
            viewModel.clearSubAgentStreaming();
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
        
        // Ensure deep agent is initialized
        if (deepAgent == null) {
            if (copilotConfig == null) {
                handleError("Copilot settings not configured. Please configure Copilot settings.", null);
                return;
            }
            if (currentProgram == null) {
                handleError("No program loaded. Please open a program to use Copilot.", null);
                return;
            }
            initializeAgent();
            if (deepAgent == null) {
                handleError("Copilot agent failed to initialize. Please check logs.", null);
                return;
            }
        }
        
        // Send message to deep agent asynchronously
        currentRunFuture = CompletableFuture.supplyAsync(() -> {
            try {
                NodeOutput<CopilotDeepState> lastOutput = null;
                for (NodeOutput<CopilotDeepState> output : (Iterable<NodeOutput<CopilotDeepState>>) () ->
                        deepAgent.stream(message).stream().iterator()) {
                    if (cancellationMonitor != null && cancellationMonitor.isCancelled()) {
                        Msg.info(this, "Agent run cancelled by user");
                        break;
                    }
                    lastOutput = output;
                    if (output == null) {
                        continue;
                    }
                    CopilotDeepState state = output.state();
                    if (state == null || viewModel == null) {
                        continue;
                    }
                    CopilotDeepState snapshot = state;
                    SwingUtilities.invokeLater(() -> syncDeepStateToViewModel(snapshot, viewModel));
                }
                boolean wasCancelled = cancellationMonitor != null && cancellationMonitor.isCancelled();
                if (wasCancelled) {
                    if (deepAgent != null) {
                        deepAgent.endTrace("Cancelled by user");
                    }
                    return new DeepAgentRunResult(
                        "", System.nanoTime(), System.nanoTime(),
                        false, false, 0, List.of());
                }
                if (lastOutput == null || lastOutput.state() == null) {
                    throw new RuntimeException("Deep agent stream completed without state");
                }
                long finalStateNs = System.nanoTime();
                CopilotDeepState finalState = lastOutput.state();
                if (viewModel != null) {
                    CopilotDeepState finalSnapshot = finalState;
                    SwingUtilities.invokeLater(() -> syncDeepStateToViewModel(finalSnapshot, viewModel));
                }
                String text = finalState.finalResponse().orElse("");
                boolean usedStreamBuffer = false;
                int streamBufferChars = 0;
                if ((text == null || text.isBlank()) && streamHandler != null) {
                    String streamed = streamHandler.getCompleteMessage();
                    streamBufferChars = streamed != null ? streamed.length() : 0;
                    if (streamed != null && !streamed.isBlank()) {
                        text = streamed;
                        usedStreamBuffer = true;
                    }
                }
                boolean usedFallback = false;
                if (text == null || text.isBlank()) {
                    usedFallback = true;
                    Object fallback = deepAgent.buildFinalResponse(finalState)
                        .get(CopilotDeepState.FINAL_RESPONSE);
                    text = fallback != null ? String.valueOf(fallback) : "";
                }
                String safeText = text != null ? text : "";
                long finalTextNs = System.nanoTime();
                if (deepAgent != null) {
                    deepAgent.endTrace(safeText);
                }
                return new DeepAgentRunResult(
                    safeText,
                    finalStateNs,
                    finalTextNs,
                    usedFallback,
                    usedStreamBuffer,
                    streamBufferChars,
                    new java.util.ArrayList<>(finalState.completedTodos())
                );
            } catch (Exception e) {
                if (deepAgent != null) {
                    deepAgent.endTrace("Error: " + e.getMessage());
                }
                throw new RuntimeException("Error during agent chat: " + e.getMessage(), e);
            }
        }).thenAccept(result -> {
            long uiAppendScheduledNs = System.nanoTime();
            long runStartNs = currentRunSendStartNs;
            long lastTodoDoneNs = currentRunLastTodoDoneNs;
            long stateMs = Math.max(0L, (result.finalStateNs - runStartNs) / 1_000_000L);
            long textMs = Math.max(0L, (result.finalTextNs - runStartNs) / 1_000_000L);
            long uiScheduleMs = Math.max(0L, (uiAppendScheduledNs - runStartNs) / 1_000_000L);
            long todoTailMs = lastTodoDoneNs > 0L
                ? Math.max(0L, (result.finalTextNs - lastTodoDoneNs) / 1_000_000L)
                : -1L;
            Msg.info(this,
                "DeepAgent timing: stateMs=" + stateMs
                    + " textMs=" + textMs
                    + " uiScheduleMs=" + uiScheduleMs
                    + " todoTailMs=" + todoTailMs
                    + " usedFallback=" + result.usedFallback
                    + " usedStreamBuffer=" + result.usedStreamBuffer
                    + " streamBufferChars=" + result.streamBufferChars);

            // Persist session notes so subsequent runs (after restart) know what was explored
            if (artifactStorage != null && !result.completedTodos.isEmpty()) {
                artifactStorage.appendSessionEntry(message, result.completedTodos, result.response);
            }

            boolean cancelled = cancellationMonitor != null && cancellationMonitor.isCancelled();

            // Use view-model if available, otherwise update provider directly
            SwingUtilities.invokeLater(() -> {
                if (!cancelled && deepAgentMemoryAdapter != null) {
                    deepAgentMemoryAdapter.recordTurn(
                        dev.langchain4j.data.message.UserMessage.from(message),
                        dev.langchain4j.data.message.AiMessage.from(result.response)
                    );
                }
                if (viewModel != null) {
                    viewModel.setLoading(false);
                    viewModel.setThinking(false, null);
                    viewModel.setTodoMinimized(true);
                    if (!cancelled) {
                        List<CopilotViewModel.Message> messages = viewModel.getMessages();
                        if (!messages.isEmpty()) {
                            CopilotViewModel.Message last = messages.get(messages.size() - 1);
                            if (!last.isFromUser() && (last.getText() == null || last.getText().isEmpty())) {
                                viewModel.appendToLastMessage(result.response);
                            }
                        }
                    }
                } else if (!cancelled) {
                    provider.appendMessage("Zenyard: " + result.response);
                }
            });
        }).exceptionally(throwable -> {
            handleError("Error: " + throwable.getMessage(), throwable);
            return null;
        });
    }
    
    private void handleError(String errorMsg, Throwable throwable) {
        Throwable rootCause = findRootCause(throwable);
        final String finalErrorMsg = getUserFriendlyErrorMessage(errorMsg, rootCause, throwable);
        logCopilotException(finalErrorMsg, throwable, rootCause);
        
        // Use view-model if available, otherwise update provider directly
        SwingUtilities.invokeLater(() -> {
            if (viewModel != null) {
                viewModel.setLoading(false);
                viewModel.setThinking(false, null);
                viewModel.setTodoMinimized(true);
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

    private void logCopilotException(String finalErrorMsg, Throwable throwable, Throwable rootCause) {
        Throwable toLog = throwable != null ? throwable : rootCause;
        if (toLog != null) {
            Msg.error(this, "Copilot request failed: " + finalErrorMsg, toLog);
        } else {
            Msg.error(this, "Copilot request failed: " + finalErrorMsg);
        }
    }

    private String getUserFriendlyErrorMessage(String fallbackErrorMsg, Throwable rootCause, Throwable throwable) {
        if (isLikelyVertexThrottlingError(throwable)) {
            return "Vertex AI request was throttled because your quota or rate limit was exceeded. "
                + "Wait a minute and try again, or request a quota increase in Google Cloud Vertex AI.";
        }

        if (rootCause instanceof ApiException apiException) {
            if (apiException.getCode() == 401) {
                return "Authentication failed: your Zenyard API key is invalid or expired. "
                    + "Update it in Tools -> Zenyard -> Configuration and try again.";
            }
            if (apiException.getCode() == 429) {
                return "Request was throttled due to a quota or rate limit. "
                    + "Please wait a minute and try again.";
            }
            return "API Error: " + apiException.getMessage();
        }

        if (rootCause instanceof AuthenticationException || isLikelyModelAuthenticationError(throwable)) {
            return "Authentication failed when contacting the AI provider. "
                + "Your model API key appears invalid or expired. "
                + "Update your Copilot model API key in Tools -> Zenyard -> Configuration and try again.";
        }

        if (rootCause != null && rootCause.getMessage() != null && !rootCause.getMessage().isBlank()) {
            return "Error: " + rootCause.getMessage();
        }
        return fallbackErrorMsg;
    }

    private void refreshPythonAvailabilityWarning() {
        if (viewModel == null) {
            return;
        }
        boolean pythonAvailable = RunPythonScriptTool.isPythonAvailable();
        viewModel.setPythonUnavailableWarning(!pythonAvailable,
            pythonAvailable ? null : PYTHON_UNAVAILABLE_WARNING_MESSAGE);
    }

    private void refreshPythonAvailabilityWarning(List<Object> tools) {
        if (viewModel == null || tools == null) {
            return;
        }
        boolean pythonToolRegistered = tools.stream()
            .anyMatch(toolObject -> toolObject instanceof RunPythonScriptTool);
        viewModel.setPythonUnavailableWarning(!pythonToolRegistered,
            pythonToolRegistered ? null : PYTHON_UNAVAILABLE_WARNING_MESSAGE);
    }

    private boolean isLikelyModelAuthenticationError(Throwable throwable) {
        return exceptionChainMatches(throwable, lowerMessage ->
            containsAny(lowerMessage,
                "invalid api key",
                "auth_error",
                "authentication",
                "\"code\":\"401\"",
                "'code':'401'",
                "\"code\":401",
                "code: 401"));
    }

    private boolean isLikelyVertexThrottlingError(Throwable throwable) {
        return exceptionChainMatches(throwable, lowerMessage -> {
            boolean hasThrottlingMarker = containsAny(lowerMessage,
                "throttling_error",
                "resource_exhausted",
                "quota exceeded",
                "rate limit",
                "rate_limit",
                "too many requests",
                "\"code\":\"429\"",
                "\"code\":429",
                "code: 429");
            boolean hasVertexMarker = containsAny(lowerMessage,
                "vertex",
                "vertex_ai",
                "aiplatform.googleapis.com",
                "online_prediction_input_tokens_per_minute_per_base_model");
            return hasThrottlingMarker && hasVertexMarker;
        });
    }

    private boolean exceptionChainMatches(
            Throwable throwable,
            java.util.function.Predicate<String> messageMatcher) {
        if (throwable == null || messageMatcher == null) {
            return false;
        }
        java.util.Set<Throwable> visited = new java.util.HashSet<>();
        Throwable current = throwable;
        while (current != null && visited.add(current)) {
            String message = current.getMessage();
            if (message != null && messageMatcher.test(message.toLowerCase(java.util.Locale.ROOT))) {
                return true;
            }
            current = current.getCause();
        }
        return false;
    }

    private static boolean containsAny(String text, String... needles) {
        if (text == null || needles == null) {
            return false;
        }
        for (String needle : needles) {
            if (needle != null && !needle.isBlank() && text.contains(needle)) {
                return true;
            }
        }
        return false;
    }

    private Throwable findRootCause(Throwable throwable) {
        if (throwable == null) {
            return null;
        }
        Throwable rootCause = throwable;
        while (rootCause.getCause() != null && rootCause.getCause() != rootCause) {
            rootCause = rootCause.getCause();
        }
        return rootCause;
    }

    private boolean shouldSanitizeToolMessages(CopilotConfig config) {
        if (config == null) {
            return false;
        }
        String policy = getStringParam(config, "tool_message_sanitize", "toolMessageSanitize", "tool_message_policy");
        if ("always".equalsIgnoreCase(policy) || "true".equalsIgnoreCase(policy)) {
            return true;
        }
        if ("never".equalsIgnoreCase(policy) || "false".equalsIgnoreCase(policy)) {
            return false;
        }
        Boolean explicit = getBooleanParam(config, false, "sanitize_tool_messages", "sanitizeToolMessages");
        return explicit != null && explicit;
    }

    private CopilotDeepAgentConfig buildDeepAgentConfig(CopilotConfig config) {
        if (config == null) {
            return CopilotDeepAgentConfig.defaults();
        }

        int recursionLimit = getIntParam(config, 1000, "deepagent_recursion_limit", "deepAgentRecursionLimit");
        boolean debug = getBooleanParam(config, false, "deepagent_debug", "deepAgentDebug");
        boolean checkpointing = getBooleanParam(config, false, "deepagent_checkpointing", "deepAgentCheckpointing");
        boolean releaseThread = getBooleanParam(config, false, "deepagent_release_thread", "deepAgentReleaseThread");
        boolean interruptBeforeEdge = getBooleanParam(config, false, "deepagent_interrupt_before_edge", "deepAgentInterruptBeforeEdge");
        boolean parallelToolExecution = getBooleanParam(
            config, false, "deepagent_parallel_tools", "deepAgentParallelTools");
        int parallelToolMaxConcurrency = getIntParam(
            config, 4, "deepagent_parallel_tool_concurrency", "deepAgentParallelToolConcurrency");
        int responseStreamingTimeoutMs = getIntParam(
            config, 120_000, "deepagent_response_stream_timeout_ms", "deepAgentResponseStreamTimeoutMs");

        java.util.Set<String> returnDirectTools = getStringSetParam(
            config, "deepagent_return_direct_tools", "deepAgentReturnDirectTools");
        java.util.Set<String> interruptsBefore = getStringSetParam(
            config, "deepagent_interrupt_before", "deepAgentInterruptBefore");
        java.util.Set<String> interruptsAfter = getStringSetParam(
            config, "deepagent_interrupt_after", "deepAgentInterruptAfter");
        String graphId = getStringParam(config, "deepagent_graph_id", "deepAgentGraphId");
        if (graphId == null || graphId.isBlank()) {
            graphId = "copilot-deepagent";
        }

        org.bsc.langgraph4j.checkpoint.BaseCheckpointSaver checkpointSaver = null;
        if (checkpointing || !interruptsBefore.isEmpty() || !interruptsAfter.isEmpty()) {
            checkpointSaver = new org.bsc.langgraph4j.checkpoint.MemorySaver();
        }

        int contextWindowTokens = getIntParam(
            config, 200_000, "deepagent_context_window_tokens", "deepAgentContextWindowTokens");
        int summarizationKeepMessages = getIntParam(
            config, 20, "deepagent_summarization_keep_messages", "deepAgentSummarizationKeepMessages");
        int toolArgTruncateThreshold = getIntParam(
            config, 5000, "deepagent_tool_arg_truncate_threshold", "deepAgentToolArgTruncateThreshold");
        long subAgentTimeoutMs = (long) getIntParam(
            config, 540_000, "deepagent_subagent_timeout_ms", "deepAgentSubAgentTimeoutMs");
        int subAgentRecursionLimit = getIntParam(
            config, 50, "deepagent_subagent_recursion_limit", "deepAgentSubAgentRecursionLimit");
        long toolCallTimeoutMs = (long) getIntParam(
            config, 60_000, "deepagent_tool_call_timeout_ms", "deepAgentToolCallTimeoutMs");

        return new CopilotDeepAgentConfig(
            recursionLimit,
            debug,
            returnDirectTools,
            parallelToolExecution,
            parallelToolMaxConcurrency,
            responseStreamingTimeoutMs,
            "copilot-" + COPILOT_THREAD_ID,
            checkpointSaver,
            interruptsBefore,
            interruptsAfter,
            releaseThread,
            interruptBeforeEdge,
            graphId,
            contextWindowTokens,
            0.8,
            summarizationKeepMessages,
            toolArgTruncateThreshold,
            subAgentTimeoutMs,
            subAgentRecursionLimit,
            toolCallTimeoutMs
        );
    }

    private String getStringParam(CopilotConfig config, String... keys) {
        if (config == null || config.getAdditionalParams() == null || keys == null) {
            return null;
        }
        for (String key : keys) {
            if (key == null || key.isBlank()) {
                continue;
            }
            Object value = config.getAdditionalParams().get(key);
            if (value == null) {
                continue;
            }
            String text = String.valueOf(value).trim();
            if (!text.isBlank()) {
                return text;
            }
        }
        return null;
    }


    private Integer getIntParam(CopilotConfig config, int defaultValue, String... keys) {
        String text = getStringParam(config, keys);
        if (text == null) {
            return defaultValue;
        }
        try {
            return Integer.parseInt(text);
        } catch (NumberFormatException ex) {
            return defaultValue;
        }
    }

    private Boolean getBooleanParam(CopilotConfig config, boolean defaultValue, String... keys) {
        String text = getStringParam(config, keys);
        if (text == null) {
            return defaultValue;
        }
        return Boolean.parseBoolean(text);
    }

    private java.util.Set<String> getStringSetParam(CopilotConfig config, String... keys) {
        if (config == null || config.getAdditionalParams() == null || keys == null) {
            return java.util.Set.of();
        }
        for (String key : keys) {
            if (key == null || key.isBlank()) {
                continue;
            }
            Object value = config.getAdditionalParams().get(key);
            if (value == null) {
                continue;
            }
            if (value instanceof java.util.Collection<?> collection) {
                java.util.Set<String> out = new java.util.LinkedHashSet<>();
                for (Object item : collection) {
                    if (item == null) {
                        continue;
                    }
                    String text = String.valueOf(item).trim();
                    if (!text.isBlank()) {
                        out.add(text);
                    }
                }
                return out;
            }
            String text = String.valueOf(value);
            if (text == null || text.isBlank()) {
                continue;
            }
            String[] split = text.split(",");
            java.util.Set<String> out = new java.util.LinkedHashSet<>();
            for (String item : split) {
                if (item == null) {
                    continue;
                }
                String normalized = item.trim();
                if (!normalized.isBlank()) {
                    out.add(normalized);
                }
            }
            return out;
        }
        return java.util.Set.of();
    }

    public void setTodoMinimized(boolean minimized) {
        if (viewModel != null) {
            viewModel.setTodoMinimized(minimized);
        }
    }

    private com.zenyard.ghidra.copilot.deepagent.CopilotTaskToolBuilder.SubAgentProgressListener
            createSubAgentProgressListener() {
        return new com.zenyard.ghidra.copilot.deepagent.CopilotTaskToolBuilder.SubAgentProgressListener() {
            @Override
            public void onSubAgentStart(String agentType, String description) {
                if (viewModel != null) {
                    SwingUtilities.invokeLater(() -> {
                        viewModel.setThinking(true, "Running " + agentType + " subagent...");
                        viewModel.setSubAgentStreaming(agentType, "");
                    });
                }
            }

            @Override
            public void onSubAgentEnd(String agentType, boolean success) {
                if (viewModel != null) {
                    SwingUtilities.invokeLater(() -> {
                        viewModel.setThinking(true, "Thinking...");
                    });
                }
            }

            @Override
            public void onSubAgentToken(String agentType, String token) {
                if (viewModel != null) {
                    SwingUtilities.invokeLater(() ->
                        viewModel.appendSubAgentToken(token));
                }
            }
        };
    }

    private ToolExecutionListener createToolExecutionListener(CopilotViewModel model) {
        return new ToolExecutionListener() {
            @Override
            public void onToolStart(String toolName, java.util.Map<String, Object> arguments) {
                SwingUtilities.invokeLater(() ->
                    model.setThinking(true, "Running " + toolName + "..."));
            }

            @Override
            public void onToolSuccess(String toolName, long durationMs) {
                SwingUtilities.invokeLater(() -> {
                    model.addToolHistory(toolName);
                    model.setThinking(false, null);
                });
            }

            @Override
            public void onToolError(String toolName, Throwable error, long durationMs) {
                SwingUtilities.invokeLater(() ->
                    model.setThinking(false, null));
            }
        };
    }

    private void syncDeepStateToViewModel(CopilotDeepState state, CopilotViewModel model) {
        if (state == null || model == null) {
            return;
        }
        String previousActive = lastObservedActiveTodo;
        String active = state.activeTodo().orElse("");
        long now = System.currentTimeMillis();
        if (!java.util.Objects.equals(lastObservedActiveTodo, active)) {
            lastObservedActiveTodo = active;
            lastObservedActiveTodoSinceMs = now;
        }
        if (previousActive != null && !previousActive.isBlank() && active.isBlank()) {
            currentRunLastTodoDoneNs = System.nanoTime();
        }
        long activeAgeMs = !active.isBlank() ? Math.max(0L, now - lastObservedActiveTodoSinceMs) : 0L;
        List<String> incomingTodos = new ArrayList<>(state.todos());
        List<String> displayTodos = new ArrayList<>(incomingTodos);
        String displayActive = active;
        List<String> displayCompleted = new ArrayList<>(state.completedTodos());
        List<String> displayFailed = new ArrayList<>(state.failedTodos());
        List<String> toolEvents = new ArrayList<>(state.toolEvents());

        // Deep state updates can be incremental; merge with current view-model state
        // to avoid transient list replacement/flicker in Task Progress.
        if (model.isLoading() || model.isThinking()) {
            java.util.LinkedHashSet<String> mergedTodos = new java.util.LinkedHashSet<>(model.getTodos());
            mergedTodos.addAll(incomingTodos);
            displayTodos = new ArrayList<>(mergedTodos);

            java.util.LinkedHashSet<String> mergedCompleted = new java.util.LinkedHashSet<>(model.getCompletedTodos());
            mergedCompleted.addAll(displayCompleted);
            displayCompleted = new ArrayList<>(mergedCompleted);

            java.util.LinkedHashSet<String> mergedFailed = new java.util.LinkedHashSet<>(model.getFailedTodos());
            mergedFailed.addAll(displayFailed);
            displayFailed = new ArrayList<>(mergedFailed);

            if ((displayActive == null || displayActive.isBlank())) {
                String priorActive = model.getActiveTodo();
                if (priorActive != null && !priorActive.isBlank() && displayTodos.contains(priorActive)) {
                    displayActive = priorActive;
                }
            }
        }

        String effectiveActive = displayActive;
        if (!displayActive.isBlank() && activeAgeMs > 5000L) {
            effectiveActive = "";
        }
        model.syncTodoState(
            displayTodos,
            effectiveActive.isBlank() ? null : effectiveActive,
            displayCompleted,
            displayFailed
        );
        String toolBatchSignature = String.join("\u001f", toolEvents);
        if (!toolEvents.isEmpty() && !toolBatchSignature.equals(lastObservedToolBatchSignature)) {
            for (String toolName : toolEvents) {
                model.addToolHistory(toolName);
            }
            lastObservedToolBatchSignature = toolBatchSignature;
        }
    }
}

