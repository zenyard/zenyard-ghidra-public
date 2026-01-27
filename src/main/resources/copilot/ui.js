(() => {
  const chat = document.getElementById("chat");
  const input = document.getElementById("input");
  const sendBtn = document.getElementById("sendBtn");
  const stopBtn = document.getElementById("stopBtn");
  const typingIndicator = document.getElementById("typingIndicator");
  const app = document.getElementById("app");
  const bridgeEl = document.getElementById("dom-bridge");

  const state = {
    messages: [],
    loading: false,
    error: null,
    thinking: false,
    thinkingText: null,
  };

  let lastStreamingIndex = null;
  let lastStreamingText = "";

  // Track rendered positions per message for incremental rendering
  const renderedPositions = new Map();

  function dispatchBridgeEvent(type, payload) {
    if (!bridgeEl) {
      return false;
    }
    try {
      bridgeEl.dataset.payload = payload ? JSON.stringify(payload) : "";
    } catch (e) {
      bridgeEl.dataset.payload = "";
    }
    try {
      const event = new CustomEvent(type, { detail: payload });
      bridgeEl.dispatchEvent(event);
      return true;
    } catch (e) {
      return false;
    }
  }

  function logToHost(message) {
    dispatchBridgeEvent("copilot-log", { message });
    try {
      if (window.console && typeof console.log === "function") {
        console.log(message);
      }
    } catch (e) {
      // ignore
    }
  }

  marked.setOptions({
    gfm: true,
    breaks: true,
    mangle: false,
    headerIds: false,
  });

  function sanitize(html) {
    return DOMPurify.sanitize(html, { USE_PROFILES: { html: true } });
  }

  function normalizeLanguage(codeEl) {
    const className = codeEl.className || "";
    const match = className.match(/language-([a-z0-9-]+)/i);
    return match ? match[1] : "text";
  }

  function enhanceCodeBlock(pre, codeEl) {
    const wrapper = document.createElement("div");
    wrapper.className = "code-block";

    const toolbar = document.createElement("div");
    toolbar.className = "code-toolbar";

    const langLabel = document.createElement("span");
    langLabel.textContent = normalizeLanguage(codeEl);

    const actions = document.createElement("div");
    actions.className = "code-actions";

    const copyBtn = document.createElement("button");
    copyBtn.className = "code-btn";
    copyBtn.textContent = "Copy";
    copyBtn.addEventListener("click", () => copyToClipboard(codeEl.innerText, copyBtn));

    const collapseBtn = document.createElement("button");
    collapseBtn.className = "code-btn";
    collapseBtn.textContent = "Collapse";
    collapseBtn.addEventListener("click", () => {
      wrapper.classList.toggle("collapsed");
      collapseBtn.textContent = wrapper.classList.contains("collapsed") ? "Expand" : "Collapse";
    });

    actions.append(copyBtn, collapseBtn);
    toolbar.append(langLabel, actions);

    wrapper.append(toolbar, pre.cloneNode(true));
    pre.replaceWith(wrapper);
  }

  function enhanceCodeBlocks(container) {
    const blocks = container.querySelectorAll("pre > code");
    blocks.forEach((codeEl) => {
      const pre = codeEl.parentElement;
      if (pre && pre.parentElement && pre.parentElement.classList.contains("code-block")) {
        return;
      }
      enhanceCodeBlock(pre, codeEl);
    });

    container.querySelectorAll("pre code").forEach((codeEl) => {
      if (window.Prism) {
        Prism.highlightElement(codeEl);
      }
    });
  }

  // Helper function to detect block type at a given position
  function detectBlockType(text, position) {
    const lineStart = text.lastIndexOf('\n', position - 1) + 1;
    const line = text.substring(lineStart, position).trim();
    
    if (line.startsWith('```')) {
      return 'code';
    }
    if (/^#{1,6}\s/.test(line)) {
      return 'header';
    }
    if (/^[-*+]\s/.test(line) || /^\d+\.\s/.test(line)) {
      return 'list';
    }
    if (line.length === 0) {
      return 'blank';
    }
    return 'paragraph';
  }

  // Find complete blocks in text starting from a position
  function findCompleteBlocks(text, startPos) {
    const blocks = [];
    let pos = startPos;
    let inCodeBlock = false;
    let codeBlockStart = -1;
    let currentBlockStart = startPos;
    let currentBlockType = null;

    // Check if we're already in a code block
    const textBeforeStart = text.substring(0, startPos);
    const codeBlockMatches = textBeforeStart.match(/```/g);
    if (codeBlockMatches && codeBlockMatches.length % 2 === 1) {
      inCodeBlock = true;
      codeBlockStart = textBeforeStart.lastIndexOf('```');
    }

    // Split into lines for easier processing
    const lines = text.substring(startPos).split('\n');
    let lineOffset = startPos;

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const lineStart = lineOffset;
      const lineEnd = lineStart + line.length;
      const isLastLine = i === lines.length - 1;
      const nextLine = i + 1 < lines.length ? lines[i + 1] : '';

      // Check for code block markers
      if (line.trim().startsWith('```')) {
        if (inCodeBlock) {
          // Closing code block - complete the code block
          const blockEnd = lineEnd + (isLastLine ? 0 : 1); // Include newline if not last
          const blockText = text.substring(codeBlockStart, blockEnd);
          blocks.push({
            type: 'code',
            text: blockText,
            start: codeBlockStart,
            end: blockEnd
          });
          inCodeBlock = false;
          codeBlockStart = -1;
          currentBlockStart = blockEnd;
          currentBlockType = null;
          lineOffset = blockEnd;
          continue;
        } else {
          // Opening code block
          // Complete any previous block
          if (currentBlockType && currentBlockStart < lineStart) {
            const prevBlockText = text.substring(currentBlockStart, lineStart);
            if (prevBlockText.trim().length > 0) {
              blocks.push({
                type: currentBlockType,
                text: prevBlockText,
                start: currentBlockStart,
                end: lineStart
              });
            }
          }
          inCodeBlock = true;
          codeBlockStart = lineStart;
          currentBlockStart = lineEnd + (isLastLine ? 0 : 1);
          currentBlockType = null;
          lineOffset = lineEnd + (isLastLine ? 0 : 1);
          continue;
        }
      }

      if (inCodeBlock) {
        lineOffset = lineEnd + (isLastLine ? 0 : 1);
        continue;
      }

      // Check for headers
      const headerMatch = line.match(/^(#{1,6})\s+(.+)$/);
      if (headerMatch) {
        // Complete previous block if any
        if (currentBlockType && currentBlockStart < lineStart) {
          const prevBlockText = text.substring(currentBlockStart, lineStart);
          if (prevBlockText.trim().length > 0) {
            blocks.push({
              type: currentBlockType,
              text: prevBlockText,
              start: currentBlockStart,
              end: lineStart
            });
          }
        }
        // Header is complete
        const blockEnd = lineEnd + (isLastLine ? 0 : 1);
        blocks.push({
          type: 'header',
          text: text.substring(lineStart, blockEnd),
          start: lineStart,
          end: blockEnd
        });
        currentBlockStart = blockEnd;
        currentBlockType = null;
        lineOffset = blockEnd;
        continue;
      }

      // Check for list items
      const listMatch = line.match(/^([-*+]|\d+\.)\s+/);
      if (listMatch) {
        // Check if list continues or ends
        const listContinues = nextLine.trim().length > 0 && 
          (nextLine.match(/^([-*+]|\d+\.)\s+/) || nextLine.match(/^\s+/));
        
        if (currentBlockType === 'list') {
          // Continue current list
          lineOffset = lineEnd + (isLastLine ? 0 : 1);
          continue;
        } else {
          // Start new list
          // Complete previous block if any
          if (currentBlockType && currentBlockStart < lineStart) {
            const prevBlockText = text.substring(currentBlockStart, lineStart);
            if (prevBlockText.trim().length > 0) {
              blocks.push({
                type: currentBlockType,
                text: prevBlockText,
                start: currentBlockStart,
                end: lineStart
              });
            }
          }
          currentBlockStart = lineStart;
          currentBlockType = 'list';
          
          // If list doesn't continue, complete it
          if (!listContinues) {
            const blockEnd = lineEnd + (isLastLine ? 0 : 1);
            blocks.push({
              type: 'list',
              text: text.substring(lineStart, blockEnd),
              start: lineStart,
              end: blockEnd
            });
            currentBlockStart = blockEnd;
            currentBlockType = null;
          }
          lineOffset = lineEnd + (isLastLine ? 0 : 1);
          continue;
        }
      }

      // Handle paragraphs
      if (line.trim().length > 0) {
        // Check if paragraph should end (blank line or new block type)
        const shouldEndParagraph = nextLine.trim().length === 0 || 
          nextLine.match(/^(#{1,6})\s+/) ||
          nextLine.match(/^([-*+]|\d+\.)\s+/) ||
          nextLine.trim().startsWith('```');

        if (currentBlockType === 'paragraph') {
          if (shouldEndParagraph) {
            // Complete paragraph
            const blockEnd = lineEnd + (isLastLine ? 0 : 1);
            blocks.push({
              type: 'paragraph',
              text: text.substring(currentBlockStart, blockEnd),
              start: currentBlockStart,
              end: blockEnd
            });
            currentBlockStart = blockEnd;
            currentBlockType = null;
          }
        } else {
          // Start new paragraph
          if (currentBlockType && currentBlockStart < lineStart) {
            const prevBlockText = text.substring(currentBlockStart, lineStart);
            if (prevBlockText.trim().length > 0) {
              blocks.push({
                type: currentBlockType,
                text: prevBlockText,
                start: currentBlockStart,
                end: lineStart
              });
            }
          }
          currentBlockStart = lineStart;
          currentBlockType = 'paragraph';
          
          if (shouldEndParagraph) {
            const blockEnd = lineEnd + (isLastLine ? 0 : 1);
            blocks.push({
              type: 'paragraph',
              text: text.substring(lineStart, blockEnd),
              start: lineStart,
              end: blockEnd
            });
            currentBlockStart = blockEnd;
            currentBlockType = null;
          }
        }
      } else {
        // Blank line - end current paragraph if any
        if (currentBlockType === 'paragraph' && currentBlockStart < lineStart) {
          const blockEnd = lineStart;
          blocks.push({
            type: 'paragraph',
            text: text.substring(currentBlockStart, blockEnd),
            start: currentBlockStart,
            end: blockEnd
          });
          currentBlockStart = blockEnd;
          currentBlockType = null;
        }
      }

      lineOffset = lineEnd + (isLastLine ? 0 : 1);
    }

    // Return the position up to which we have complete blocks
    const lastCompletePos = blocks.length > 0 ? blocks[blocks.length - 1].end : startPos;
    return { blocks, lastCompletePos, inCodeBlock, currentBlockStart, currentBlockType };
  }

  // Render incremental markdown
  function renderIncrementalMarkdown(text, messageEl) {
    const messageIndex = messageEl.dataset.index;
    const lastRenderedPos = renderedPositions.get(messageIndex) || 0;

    if (text.length <= lastRenderedPos) {
      return { blocks: [], streamingText: text, newRenderedPos: lastRenderedPos };
    }

    const result = findCompleteBlocks(text, lastRenderedPos);

    // Get the incomplete portion
    const incompleteStart = result.lastCompletePos;
    const streamingText = text.substring(incompleteStart);

    // Update rendered position
    const newRenderedPos = result.lastCompletePos;
    renderedPositions.set(messageIndex, newRenderedPos);

    return { blocks: result.blocks, streamingText, newRenderedPos };
  }

  function copyToClipboard(text, button) {
    const done = () => {
      const original = button.textContent;
      button.textContent = "Copied";
      setTimeout(() => {
        button.textContent = original;
      }, 1200);
    };

    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(done).catch(() => fallbackCopy(text, done));
      return;
    }
    fallbackCopy(text, done);
  }

  function fallbackCopy(text, callback) {
    const textarea = document.createElement("textarea");
    textarea.value = text;
    textarea.style.position = "fixed";
    textarea.style.opacity = "0";
    document.body.appendChild(textarea);
    textarea.select();
    try {
      document.execCommand("copy");
      callback();
    } finally {
      document.body.removeChild(textarea);
    }
  }

  function createBubble(message, index) {
    const container = document.createElement("div");
    container.className = `message ${message.fromUser ? "user" : "assistant"}`;
    container.dataset.index = String(index);

    if (message.chips && message.chips.length) {
      const chips = document.createElement("div");
      chips.className = "chips";
      message.chips.forEach((chip) => {
        const chipEl = document.createElement("span");
        chipEl.className = "chip";
        chipEl.textContent = chip;
        chips.appendChild(chipEl);
      });
      container.appendChild(chips);
    }

    const bubble = document.createElement("div");
    bubble.className = "bubble";
    container.appendChild(bubble);

    return container;
  }

  function updateStreaming(messageEl, text) {
    const bubble = messageEl.querySelector(".bubble");
    
    // Initialize structure if needed
    let renderedContent = bubble.querySelector(".rendered-content");
    let streamingContent = bubble.querySelector(".streaming-content");
    
    if (!renderedContent) {
      bubble.innerHTML = "";
      renderedContent = document.createElement("div");
      renderedContent.className = "rendered-content";
      bubble.appendChild(renderedContent);
    }
    
    if (!streamingContent) {
      streamingContent = document.createElement("div");
      streamingContent.className = "streaming-content";
      bubble.appendChild(streamingContent);
    }

    // Render incremental markdown
    const result = renderIncrementalMarkdown(text, messageEl);
    
    // Render new complete blocks
    if (result.blocks.length > 0) {
      result.blocks.forEach(block => {
        const blockHTML = marked.parse(block.text);
        const tempDiv = document.createElement("div");
        tempDiv.innerHTML = sanitize(blockHTML);
        
        // Append rendered block content directly to renderedContent
        while (tempDiv.firstChild) {
          renderedContent.appendChild(tempDiv.firstChild);
        }
      });
      
      // Enhance code blocks in newly rendered content
      enhanceCodeBlocks(renderedContent);
    }
    
    // Update streaming content (incomplete portion)
    streamingContent.textContent = result.streamingText;
    
    ensureStreamingIndicator(bubble);

    bubble.dataset.finalized = "false";
    messageEl.dataset.lastText = text;
    lastStreamingText = text;
    lastStreamingIndex = Number(messageEl.dataset.index);
  }

  function finalizeMarkdown(messageEl, text) {
    const bubble = messageEl.querySelector(".bubble");
    const messageIndex = messageEl.dataset.index;
    
    // Clear rendered position tracking for this message
    renderedPositions.delete(messageIndex);
    
    // Render final markdown
    const html = marked.parse(text);
    bubble.innerHTML = sanitize(html);
    enhanceCodeBlocks(bubble);
    bubble.dataset.finalized = "true";
    messageEl.dataset.lastText = text;
    lastStreamingText = "";
    lastStreamingIndex = null;
  }

  function ensureStreamingIndicator(bubble) {
    let indicator = bubble.querySelector(".streaming-indicator");
    if (!indicator) {
      indicator = document.createElement("div");
      indicator.className = "streaming-indicator";

      const dots = document.createElement("div");
      dots.className = "streaming-dots";
      for (let i = 0; i < 3; i += 1) {
        const dot = document.createElement("span");
        dot.className = "streaming-dot";
        dots.appendChild(dot);
      }

      const label = document.createElement("span");
      label.className = "streaming-label";
      label.textContent = "Streaming";

      indicator.appendChild(dots);
      indicator.appendChild(label);
      bubble.appendChild(indicator);
    }
  }

  function renderError(error) {
    const existing = chat.querySelector(".error-banner");
    if (!error && existing) {
      existing.remove();
      return;
    }
    if (!error) {
      return;
    }
    const banner = existing || document.createElement("div");
    banner.className = "error-banner";
    banner.textContent = error;
    if (!existing) {
      chat.prepend(banner);
    }
  }

  function renderMessages(nextState) {
    if (nextState.messages.length < state.messages.length) {
      chat.innerHTML = "";
      renderedPositions.clear();
    }

    renderError(nextState.error);

    nextState.messages.forEach((message, index) => {
      let messageEl = chat.querySelector(`.message[data-index="${index}"]`);
      if (!messageEl) {
        messageEl = createBubble(message, index);
        chat.appendChild(messageEl);
      }

      if (message.fromUser) {
        const bubble = messageEl.querySelector(".bubble");
        bubble.textContent = message.text;
        return;
      }

      if (nextState.loading && index === nextState.messages.length - 1) {
        updateStreaming(messageEl, message.text || "");
      } else {
        const bubble = messageEl.querySelector(".bubble");
        const lastText = messageEl.dataset.lastText || "";
        const shouldFinalize = bubble.dataset.finalized !== "true" || lastText !== message.text;
        if (message.text && shouldFinalize) {
          finalizeMarkdown(messageEl, message.text);
        }
      }
    });

    const showThinking = Boolean(nextState.loading || nextState.thinking);
    typingIndicator.classList.toggle("hidden", !showThinking);
    if (showThinking) {
      const label = typingIndicator.querySelector(".typing-label");
      if (label) {
        label.textContent = nextState.thinkingText || "Thinking...";
      }
    }
    if (stopBtn) {
      stopBtn.classList.toggle("hidden", !(nextState.loading || nextState.thinking));
    }
    chat.scrollTop = chat.scrollHeight;
  }

  function setState(nextState) {
    logToHost("CopilotUI.setState invoked");
    state.messages = nextState.messages || [];
    state.loading = Boolean(nextState.loading);
    state.error = nextState.error || null;
    state.thinking = Boolean(nextState.thinking);
    state.thinkingText = nextState.thinkingText || null;
    logToHost("CopilotUI.darkTheme type=" + typeof nextState.darkTheme +
      " value=" + String(nextState.darkTheme));
    if (nextState.darkTheme === true || nextState.darkTheme === false) {
      const theme = nextState.darkTheme ? "dark" : "light";
      document.documentElement.dataset.theme = theme;
      document.body.dataset.theme = theme;
      if (app) {
        app.dataset.theme = theme;
      }
    }
    renderMessages(nextState);
  }

  if (window.__copilotStateQueue && Array.isArray(window.__copilotStateQueue)) {
    window.__copilotStateQueue.forEach((state) => {
      try {
        setState(state);
      } catch (e) {
        logToHost("CopilotUI failed to apply queued state: " + e.message);
      }
    });
    window.__copilotStateQueue = [];
  }

  function applyStateFromBridge() {
    if (!bridgeEl) {
      return;
    }
    const raw = bridgeEl.dataset.state;
    if (!raw) {
      return;
    }
    try {
      const parsed = JSON.parse(raw);
      setState(parsed);
    } catch (e) {
      logToHost("CopilotUI failed to parse bridge state: " + e.message);
    }
  }

  if (bridgeEl) {
    const observer = new MutationObserver((mutations) => {
      mutations.forEach((mutation) => {
        if (mutation.type === "attributes" && mutation.attributeName === "data-state") {
          applyStateFromBridge();
        }
      });
    });
    observer.observe(bridgeEl, { attributes: true, attributeFilter: ["data-state"] });
    applyStateFromBridge();
  }

  function sendMessage() {
    const text = input.value.trim();
    if (!text) {
      return;
    }
    dispatchBridgeEvent("copilot-send", { message: text });
    input.value = "";
  }

  dispatchBridgeEvent("copilot-loaded", {});
  sendBtn.addEventListener("click", sendMessage);
  stopBtn.addEventListener("click", () => {
    dispatchBridgeEvent("copilot-stop", {});
  });

  input.addEventListener("keydown", (event) => {
    if (event.key === "Enter" && !event.shiftKey) {
      event.preventDefault();
      sendMessage();
    }
  });

  document.addEventListener("focusin", (event) => {
    if (app && app.contains(event.target)) {
      dispatchBridgeEvent("copilot-focus", { focused: true });
    }
  });

  document.addEventListener("focusout", () => {
    setTimeout(() => {
      if (document.activeElement && app.contains(document.activeElement)) {
        return;
      }
      dispatchBridgeEvent("copilot-focus", { focused: false });
    }, 0);
  });


  window.CopilotUI = {
    setState,
  };
})();
