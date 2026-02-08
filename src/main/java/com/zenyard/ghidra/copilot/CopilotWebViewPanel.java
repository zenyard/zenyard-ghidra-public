package com.zenyard.ghidra.copilot;

import java.awt.BorderLayout;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import javax.swing.JPanel;
import javax.swing.SwingUtilities;
import javax.swing.Timer;

import com.google.gson.Gson;

import generic.theme.ThemeListener;
import generic.theme.ThemeManager;
import ghidra.util.Msg;
import javafx.application.Platform;
import javafx.concurrent.Worker;
import javafx.embed.swing.JFXPanel;
import javafx.scene.Scene;
import javafx.scene.input.KeyCode;
import javafx.scene.input.KeyEvent;
import javafx.scene.web.WebEngine;
import javafx.scene.web.WebView;
import netscape.javascript.JSObject;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.events.Event;
import org.w3c.dom.events.EventListener;
import org.w3c.dom.events.EventTarget;

/**
 * Swing panel hosting the full Copilot UI inside a JavaFX WebView.
 */
public class CopilotWebViewPanel extends JPanel {

    private final JFXPanel fxPanel;
    private final Gson gson;
    private volatile WebEngine webEngine;
    private volatile String pendingStateJson;
    private volatile boolean webUiFocused;
    private volatile boolean fxPanelFocused;
    private volatile CopilotJsBridge jsBridge;
    private volatile Document lastDomDocument;
    private volatile Element domBridgeElement;

    private CopilotController controller;
    private CopilotViewModel viewModel;
    private Runnable viewModelListener;
    private final ThemeListener themeListener = event -> scheduleStateUpdate();

    public CopilotWebViewPanel() {
        super(new BorderLayout());
        this.fxPanel = new JFXPanel();
        this.fxPanel.setFocusable(true);
        this.fxPanel.addFocusListener(new java.awt.event.FocusAdapter() {
            @Override
            public void focusGained(java.awt.event.FocusEvent e) {
                fxPanelFocused = true;
            }

            @Override
            public void focusLost(java.awt.event.FocusEvent e) {
                fxPanelFocused = false;
            }
        });
        this.gson = new Gson();

        add(fxPanel, BorderLayout.CENTER);
        initializeJavaFx();
        ThemeManager.getInstance().addThemeListener(themeListener);
    }

    public void setController(CopilotController controller) {
        this.controller = controller;
    }

    public void setViewModel(CopilotViewModel viewModel) {
        if (this.viewModel != null && viewModelListener != null) {
            this.viewModel.removeListener(viewModelListener);
        }
        this.viewModel = viewModel;
        if (this.viewModel != null) {
            viewModelListener = this::scheduleStateUpdate;
            this.viewModel.addListener(viewModelListener);
            scheduleStateUpdate();
        }
    }

    public void redispatchKeyEvent(java.awt.event.KeyEvent event) {
        java.awt.KeyboardFocusManager kfm =
            java.awt.KeyboardFocusManager.getCurrentKeyboardFocusManager();
        java.awt.Component target = fxPanel;
        java.awt.event.KeyEvent newEvent = new java.awt.event.KeyEvent(
            target,
            event.getID(),
            event.getWhen(),
            event.getModifiersEx(),
            event.getKeyCode(),
            event.getKeyChar(),
            event.getKeyLocation()
        );
        kfm.redispatchEvent(target, newEvent);
    }

    public boolean isFocusWithin() {
        if (webUiFocused || fxPanelFocused) {
            return true;
        }
        java.awt.Component focusOwner = java.awt.KeyboardFocusManager
            .getCurrentKeyboardFocusManager()
            .getFocusOwner();
        if (focusOwner == null) {
            return false;
        }
        return javax.swing.SwingUtilities.isDescendingFrom(focusOwner, fxPanel)
            || javax.swing.SwingUtilities.isDescendingFrom(focusOwner, this);
    }

    private void initializeJavaFx() {
        Platform.setImplicitExit(false);
        Platform.runLater(() -> {
            WebView webView = new WebView();
            webEngine = webView.getEngine();
            webEngine.setOnError(event -> Msg.error(this, "Copilot WebView error: " + event.getMessage()));
            webEngine.getLoadWorker().stateProperty().addListener((obs, oldState, newState) -> {
                if (newState == Worker.State.SUCCEEDED) {
                    installBridge();
                    installDomBridgeListeners();
                    Msg.info(this, "Copilot WebView loaded.");
                } else if (newState == Worker.State.FAILED) {
                    Msg.error(this, "Copilot WebView failed to load: " + webEngine.getLoadWorker().getException());
                }
            });

            webView.addEventFilter(KeyEvent.KEY_PRESSED, event -> {
                if (webEngine == null) {
                    return;
                }
                if (event.getCode() != KeyCode.TAB && event.getCode() != KeyCode.ENTER
                        && event.getCode() != KeyCode.UP && event.getCode() != KeyCode.DOWN) {
                    return;
                }
                try {
                    Object open = webEngine.executeScript(
                        "window.CopilotUI && window.CopilotUI.isAutocompleteOpen && window.CopilotUI.isAutocompleteOpen()"
                    );
                    if (open instanceof Boolean && (Boolean) open) {
                        if (event.getCode() == KeyCode.TAB || event.getCode() == KeyCode.ENTER) {
                            webEngine.executeScript(
                                "window.CopilotUI && window.CopilotUI.acceptAutocomplete && window.CopilotUI.acceptAutocomplete()"
                            );
                        } else if (event.getCode() == KeyCode.UP) {
                            webEngine.executeScript(
                                "window.CopilotUI && window.CopilotUI.moveAutocompleteSelection && window.CopilotUI.moveAutocompleteSelection(-1)"
                            );
                        } else if (event.getCode() == KeyCode.DOWN) {
                            webEngine.executeScript(
                                "window.CopilotUI && window.CopilotUI.moveAutocompleteSelection && window.CopilotUI.moveAutocompleteSelection(1)"
                            );
                        }
                        event.consume();
                    }
                } catch (Exception e) {
                    Msg.debug(this, "Copilot autocomplete key intercept failed: " + e.getMessage());
                }
            });

            fxPanel.setScene(new Scene(webView));
            URL uiUrl = getClass().getResource("/copilot/ui.html");
            if (uiUrl == null) {
                Msg.error(this, "Copilot UI resource not found: /copilot/ui.html");
                webEngine.loadContent("<html><body>Copilot UI failed to load.</body></html>");
                return;
            }
            try {
                String html = readResource(uiUrl);
                String baseHref = uiUrl.toExternalForm().replace("ui.html", "");
                String withBase = html.replace("<head>", "<head><base href=\"" + baseHref + "\">");
                webEngine.loadContent(withBase);
            } catch (IOException e) {
                Msg.error(this, "Failed to read Copilot UI resource: " + e.getMessage());
                webEngine.load(uiUrl.toExternalForm());
            }
        });
    }

    private void installBridge() {
        if (webEngine == null) {
            return;
        }
        if (jsBridge == null) {
            jsBridge = new CopilotJsBridge();
        }
        JSObject window = (JSObject) webEngine.executeScript("window");
        window.setMember("javaBridge", jsBridge);
        Msg.info(this, "Copilot UI bridge installed");
    }

    private void installDomBridgeListeners() {
        if (webEngine == null) {
            return;
        }
        Document doc = webEngine.getDocument();
        if (doc == null || doc == lastDomDocument) {
            return;
        }
        lastDomDocument = doc;
        Element bridge = doc.getElementById("dom-bridge");
        if (bridge == null) {
            Msg.debug(this, "Copilot DOM bridge: dom-bridge not found");
            return;
        }
        domBridgeElement = bridge;
        EventListener listener = this::handleDomBridgeEvent;
        ((EventTarget) bridge).addEventListener("copilot-send", listener, false);
        ((EventTarget) bridge).addEventListener("copilot-clear", listener, false);
        ((EventTarget) bridge).addEventListener("copilot-stop", listener, false);
        ((EventTarget) bridge).addEventListener("copilot-focus", listener, false);
        ((EventTarget) bridge).addEventListener("copilot-navigate", listener, false);
        ((EventTarget) bridge).addEventListener("copilot-autocomplete", listener, false);
        ((EventTarget) bridge).addEventListener("copilot-log", listener, false);
        ((EventTarget) bridge).addEventListener("copilot-loaded", listener, false);
        ((EventTarget) bridge).addEventListener("copilot-close", listener, false);
        Msg.info(this, "Copilot DOM bridge listeners attached");
        pushStateToDom();
    }

    private void handleDomBridgeEvent(Event event) {
        if (event == null) {
            return;
        }
        String type = event.getType();
        Map<String, Object> payload = readDomPayload();
        if ("copilot-send".equals(type)) {
            String message = getPayloadString(payload, "message");
            if (message != null && !message.isEmpty() && controller != null) {
                SwingUtilities.invokeLater(() -> controller.sendMessage(message));
            }
            return;
        }
        if ("copilot-clear".equals(type)) {
            if (controller != null) {
                SwingUtilities.invokeLater(() -> controller.clearConversation());
            }
            return;
        }
        if ("copilot-stop".equals(type)) {
            if (controller != null) {
                SwingUtilities.invokeLater(() -> controller.stop());
            }
            return;
        }
        if ("copilot-navigate".equals(type)) {
            String url = getPayloadString(payload, "url");
            if (url != null && controller != null) {
                SwingUtilities.invokeLater(() -> controller.navigateToLink(url));
            }
            return;
        }
        if ("copilot-autocomplete".equals(type)) {
            String query = getPayloadString(payload, "query");
            String requestId = getPayloadString(payload, "requestId");
            if (controller != null) {
                SwingUtilities.invokeLater(() -> controller.requestAutocomplete(query, requestId));
            }
            return;
        }
        if ("copilot-focus".equals(type)) {
            Object focused = payload.get("focused");
            if (focused instanceof Boolean) {
                webUiFocused = (Boolean) focused;
            } else if (focused instanceof String) {
                webUiFocused = Boolean.parseBoolean((String) focused);
            }
            return;
        }
        if ("copilot-loaded".equals(type)) {
            Msg.info(this, "Copilot DOM bridge loaded");
            return;
        }
        if ("copilot-log".equals(type)) {
            String message = getPayloadString(payload, "message");
            if (message != null) {
                Msg.debug(this, "Copilot UI: " + message);
            }
            return;
        }
        if ("copilot-close".equals(type)) {
            if (controller != null) {
                SwingUtilities.invokeLater(() -> controller.closePanel());
            }
            return;
        }
        Msg.debug(this, "Copilot DOM bridge: unhandled event " + type);
    }

    private Map<String, Object> readDomPayload() {
        if (domBridgeElement == null) {
            return Collections.emptyMap();
        }
        String raw = domBridgeElement.getAttribute("data-payload");
        if (raw == null || raw.isEmpty()) {
            return Collections.emptyMap();
        }
        try {
            @SuppressWarnings("unchecked")
            Map<String, Object> parsed = gson.fromJson(raw, Map.class);
            return parsed != null ? parsed : Collections.emptyMap();
        } catch (Exception e) {
            Msg.debug(this, "Copilot DOM bridge: failed to parse payload: " + e.getMessage());
            return Collections.emptyMap();
        }
    }

    private String getPayloadString(Map<String, Object> payload, String key) {
        if (payload == null) {
            return null;
        }
        Object value = payload.get(key);
        return value != null ? String.valueOf(value) : null;
    }

    private void scheduleStateUpdate() {
        if (viewModel == null) {
            return;
        }
        UiState state = buildUiState();
        pendingStateJson = gson.toJson(state);
        pushStateToDom();
    }

    private void pushStateToDom() {
        if (webEngine == null || pendingStateJson == null) {
            return;
        }
        Platform.runLater(() -> {
            if (webEngine == null || pendingStateJson == null) {
                return;
            }
            if (domBridgeElement == null) {
                Document doc = webEngine.getDocument();
                if (doc != null) {
                    domBridgeElement = doc.getElementById("dom-bridge");
                }
            }
            if (domBridgeElement != null) {
                domBridgeElement.setAttribute("data-state", pendingStateJson);
            }
        });
    }

    private UiState buildUiState() {
        List<CopilotViewModel.Message> source = viewModel.getMessages();
        List<UiMessage> mapped = new ArrayList<>(source.size());
        for (CopilotViewModel.Message message : source) {
            mapped.add(new UiMessage(
                message.getText(),
                message.isFromUser(),
                message.getTimestamp(),
                Collections.emptyList()
            ));
        }
        boolean darkTheme = ThemeManager.getInstance().isDarkTheme();
        Msg.debug(this, "Copilot UI: darkTheme = " + darkTheme);
        UiAutocomplete autocomplete = null;
        String autocompleteRequestId = viewModel.getAutocompleteRequestId();
        if (autocompleteRequestId != null) {
            autocomplete = new UiAutocomplete(
                autocompleteRequestId,
                viewModel.getAutocompleteItems()
            );
        }
        return new UiState(
            mapped,
            viewModel.isLoading(),
            viewModel.getError(),
            darkTheme,
            viewModel.isThinking(),
            viewModel.getThinkingText(),
            autocomplete
        );
    }

    private class CopilotJsBridge {
        public void sendMessage(String message) {
            if (controller == null) {
                return;
            }
            SwingUtilities.invokeLater(() -> controller.sendMessage(message));
        }

        public void clearConversation() {
            if (controller == null) {
                return;
            }
            SwingUtilities.invokeLater(() -> controller.clearConversation());
        }

        public void stop() {
            if (controller == null) {
                return;
            }
            SwingUtilities.invokeLater(() -> controller.stop());
        }

        public void logLoaded() {
            Msg.info(this, "Copilot UI loaded");
        }

        public void log(String message) {
            Msg.debug(this, "Copilot UI: " + message);
        }

        public void focusChanged(boolean focused) {
            webUiFocused = focused;
        }
    }

    private static final class UiState {
        private final List<UiMessage> messages;
        private final boolean loading;
        private final String error;
        private final boolean darkTheme;
        private final boolean thinking;
        private final String thinkingText;
        private final UiAutocomplete autocomplete;

        private UiState(
                List<UiMessage> messages,
                boolean loading,
                String error,
                boolean darkTheme,
                boolean thinking,
                String thinkingText,
                UiAutocomplete autocomplete) {
            this.messages = messages;
            this.loading = loading;
            this.error = error;
            this.darkTheme = darkTheme;
            this.thinking = thinking;
            this.thinkingText = thinkingText;
            this.autocomplete = autocomplete;
        }
    }

    private static final class UiAutocomplete {
        private final String requestId;
        private final List<CopilotViewModel.AutocompleteItem> results;

        private UiAutocomplete(String requestId, List<CopilotViewModel.AutocompleteItem> results) {
            this.requestId = requestId;
            this.results = results;
        }
    }

    private static final class UiMessage {
        private final String text;
        private final boolean fromUser;
        private final long timestamp;
        private final List<String> chips;

        private UiMessage(String text, boolean fromUser, long timestamp, List<String> chips) {
            this.text = text;
            this.fromUser = fromUser;
            this.timestamp = timestamp;
            this.chips = chips;
        }
    }


    private static String readResource(URL resourceUrl) throws IOException {
        try (InputStream input = resourceUrl.openStream();
             BufferedReader reader = new BufferedReader(new InputStreamReader(input, StandardCharsets.UTF_8))) {
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line).append('\n');
            }
            return sb.toString();
        }
    }
}
