(() => {
  const chat = document.getElementById("chat");
  const contentScroll = document.getElementById("contentScroll");
  const input = document.getElementById("input");
  const sendBtn = document.getElementById("sendBtn");
  const stopBtn = document.getElementById("stopBtn");
  const closeBtn = document.getElementById("closeBtn");
  const clearBtn = document.getElementById("clearBtn");
  const typingIndicator = document.getElementById("typingIndicator");
  const app = document.getElementById("app");
  const bridgeEl = document.getElementById("dom-bridge");
  const emptyState = document.getElementById("emptyState");
  const statusPill = document.getElementById("statusPill");
  const pythonWarningBadge = document.getElementById("pythonWarningBadge");
  const todoSection = document.getElementById("todoSection");
  const todoList = document.getElementById("todoList");
  const toolInfo = document.getElementById("toolInfo");
  const toolHistoryEl = document.getElementById("toolHistory");
  const todoToggle = document.getElementById("todoToggle");
  const subAgentBox = document.getElementById("subAgentBox");
  const subAgentTypeName = document.getElementById("subAgentTypeName");
  const subAgentStream = document.getElementById("subAgentStream");

  const state = {
    messages: [],
    loading: false,
    error: null,
    thinking: false,
    thinkingText: null,
    autocomplete: null,
    usageBlocked: false,
    usageBlockedMessage: null,
    serverBlocked: false,
    serverBlockedMessage: null,
    pythonUnavailableWarningVisible: false,
    pythonUnavailableWarningMessage: null,
    todos: [],
    activeTodo: null,
    toolHistory: [],
    completedTodos: [],
    failedTodos: [],
    todoMinimized: false,
    subAgentType: null,
    subAgentStreamText: null,
  };

  let lastStreamingIndex = null;
  let lastStreamingText = "";
  let pendingSend = false;
  let pendingTodoMinimized = null;
  let taskProgressEverRendered = false;
  let lastTaskProgressSnapshot = {
    todos: [],
    completed: [],
    failed: [],
    activeTodo: null,
  };

  const PLACEHOLDER_EMPTY = 'Start with a broad scan (e.g., "Analyze structure") or use @ to focus...';
  const PLACEHOLDER_ACTIVE = "Ask a follow-up question or use @ to reference function...";
  const SUPPORT_EMAIL = "access@zenyard.ai";

  function updatePlaceholder() {
    if (!input) {
      return;
    }
    const hasMessages = Array.isArray(state.messages) && state.messages.length > 0;
    input.dataset.placeholder = hasMessages ? PLACEHOLDER_ACTIVE : PLACEHOLDER_EMPTY;
  }

  let userScrolledUp = false;
  const SCROLL_NEAR_BOTTOM_THRESHOLD = 150;

  function isNearBottom(el) {
    return el.scrollHeight - el.scrollTop - el.clientHeight < SCROLL_NEAR_BOTTOM_THRESHOLD;
  }

  function scrollTranscriptToBottom() {
    const target = contentScroll || chat;
    if (!target) {
      return;
    }
    if (userScrolledUp) {
      return;
    }
    target.scrollTop = target.scrollHeight;
  }

  function forceScrollToBottom() {
    const target = contentScroll || chat;
    if (!target) {
      return;
    }
    userScrolledUp = false;
    target.scrollTop = target.scrollHeight;
  }

  (function initScrollTracking() {
    const target = contentScroll || chat;
    if (!target) {
      return;
    }
    target.addEventListener("scroll", () => {
      userScrolledUp = !isNearBottom(target);
    }, { passive: true });
  })();

  function resetTaskProgressUiState() {
    pendingTodoMinimized = null;
    taskProgressEverRendered = false;
    lastTaskProgressSnapshot = {
      todos: [],
      completed: [],
      failed: [],
      activeTodo: null,
    };
    state.todos = [];
    state.completedTodos = [];
    state.failedTodos = [];
    state.activeTodo = null;
    state.toolHistory = [];
    state.subAgentType = null;
    state.subAgentStreamText = null;
    if (todoList) {
      todoList.innerHTML = "";
    }
    if (todoSection) {
      todoSection.classList.add("hidden");
    }
  }

  const AUTOCOMPLETE_DEBOUNCE_MS = 200;
  const AUTOCOMPLETE_RESULT_LIMIT = 20;
  let autocompleteTimer = null;
  let autocompleteRequestCounter = 0;
  const autocompleteState = {
    open: false,
    items: [],
    activeIndex: 0,
    mention: null,
    pendingRequestId: null,
  };
  const autocompleteEl = document.createElement("div");
  autocompleteEl.className = "autocomplete hidden";
  if (app) {
    app.appendChild(autocompleteEl);
  }

  // Track rendered positions per message for incremental rendering
  const renderedPositions = new Map();

  function isPlainEnter(event) {
    if (!event) {
      return false;
    }
    const isEnterKey = event.key === "Enter"
      || event.code === "Enter"
      || event.code === "NumpadEnter"
      || event.keyCode === 13;
    return isEnterKey && !event.shiftKey && !event.ctrlKey && !event.metaKey && !event.altKey;
  }

  function isInputFocused() {
    if (!input) {
      return false;
    }
    const active = document.activeElement;
    return active === input || input.contains(active);
  }

  function isBusyState(nextState) {
    const source = nextState || state;
    return Boolean(source.loading || source.thinking || pendingSend);
  }

  function setActionButtonVisibility(button, visible) {
    if (!button) {
      return;
    }
    button.classList.toggle("is-visible", visible);
    button.classList.toggle("is-hidden", !visible);
    button.setAttribute("aria-hidden", String(!visible));
  }

  function syncActionButtons(nextState) {
    const source = nextState || state;
    const busy = isBusyState(source);
    const sendDisabled = Boolean(source.usageBlocked || source.serverBlocked || busy);
    if (sendBtn) {
      setActionButtonVisibility(sendBtn, !busy);
      sendBtn.disabled = sendDisabled;
      sendBtn.classList.toggle("disabled", sendDisabled);
    }
    if (stopBtn) {
      setActionButtonVisibility(stopBtn, busy);
    }
  }

  function hasAssistantResponse(prevMessages, nextMessages) {
    if (!Array.isArray(nextMessages) || nextMessages.length === 0) {
      return false;
    }
    const nextLast = nextMessages[nextMessages.length - 1];
    if (!nextLast || nextLast.fromUser) {
      return false;
    }
    if (!Array.isArray(prevMessages) || prevMessages.length === 0) {
      return true;
    }
    const prevLast = prevMessages[prevMessages.length - 1];
    if (!prevLast || prevLast.fromUser) {
      return true;
    }
    if (prevMessages.length !== nextMessages.length) {
      return true;
    }
    return (prevLast.text || "") !== (nextLast.text || "");
  }

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

  function handleLinkClick(event) {
    const link = event.target?.closest?.("a");
    if (!link) {
      return;
    }
    const href = link.getAttribute("href");
    if (!href || !href.startsWith("ghidra://")) {
      return;
    }
    event.preventDefault();
    event.stopPropagation();
    dispatchBridgeEvent("copilot-navigate", { url: href });
  }

  function normalizeInputContent() {
    if (!input) {
      return;
    }
    if (input.innerHTML === "<br>" || input.innerHTML === "<div><br></div>") {
      input.innerHTML = "";
    }
  }

  function setInputText(text) {
    if (!input) {
      return;
    }
    input.innerText = text;
    const range = document.createRange();
    range.selectNodeContents(input);
    range.collapse(false);
    const selection = window.getSelection();
    selection.removeAllRanges();
    selection.addRange(range);
    input.focus();
  }

  function isMentionToken(node) {
    return node && node.nodeType === Node.ELEMENT_NODE
      && node.classList.contains("mention-token");
  }

  function serializeInputToMarkdown() {
    if (!input) {
      return "";
    }
    const serializeNode = (node) => {
      if (node.nodeType === Node.TEXT_NODE) {
        return (node.textContent || "").replace(/\u200B/g, "");
      }
      if (node.nodeType !== Node.ELEMENT_NODE) {
        return "";
      }
      const tag = node.tagName;
      if (tag === "BR") {
        return "\n";
      }
      if (tag === "A") {
        const href = node.getAttribute("href");
        const label = node.textContent || "";
        return href ? `[${label}](${href})` : label;
      }
      if (node.classList && node.classList.contains("mention-token")) {
        const href = node.getAttribute("data-href");
        const label = node.textContent || "";
        return href ? `[${label}](${href})` : label;
      }
      const parts = [];
      node.childNodes.forEach((child) => {
        parts.push(serializeNode(child));
      });
      if (tag === "DIV" || tag === "P") {
        return `${parts.join("")}\n`;
      }
      return parts.join("");
    };

    const pieces = [];
    input.childNodes.forEach((child) => {
      pieces.push(serializeNode(child));
    });
    return pieces.join("").replace(/\n+$/g, "");
  }

  function findFirstTextNode(node) {
    if (!node) {
      return null;
    }
    if (node.nodeType === Node.TEXT_NODE) {
      return node;
    }
    for (let i = 0; i < node.childNodes.length; i += 1) {
      const found = findFirstTextNode(node.childNodes[i]);
      if (found) {
        return found;
      }
    }
    return null;
  }

  function findLastTextNode(node) {
    if (!node) {
      return null;
    }
    if (node.nodeType === Node.TEXT_NODE) {
      return node;
    }
    for (let i = node.childNodes.length - 1; i >= 0; i -= 1) {
      const found = findLastTextNode(node.childNodes[i]);
      if (found) {
        return found;
      }
    }
    return null;
  }

  function resolveSelectionContext() {
    const selection = window.getSelection();
    if (!selection || selection.rangeCount === 0) {
      return null;
    }
    if (!input || !input.contains(selection.focusNode)) {
      return null;
    }
    if (selection.focusNode.nodeType === Node.TEXT_NODE) {
      return { node: selection.focusNode, offset: selection.focusOffset };
    }
    if (selection.focusNode.nodeType === Node.ELEMENT_NODE) {
      const element = selection.focusNode;
      const index = selection.focusOffset;
      const before = element.childNodes[index - 1];
      const after = element.childNodes[index];
      const beforeText = findLastTextNode(before);
      if (beforeText) {
        return { node: beforeText, offset: beforeText.textContent.length };
      }
      const afterText = findFirstTextNode(after);
      if (afterText) {
        return { node: afterText, offset: 0 };
      }
    }
    return null;
  }

  function getMentionFromSelection() {
    const context = resolveSelectionContext();
    if (!context) {
      return null;
    }
    const text = context.node.textContent || "";
    const before = text.slice(0, context.offset);
    const atIndex = before.lastIndexOf("@");
    if (atIndex === -1) {
      return null;
    }
    const charBefore = atIndex > 0 ? before[atIndex - 1] : "";
    if (charBefore && !/[\s([{<>"'.,:;!?]/.test(charBefore)) {
      return null;
    }
    const query = before.slice(atIndex + 1);
    if (query.length === 0) {
      return null;
    }
    if (/\s/.test(query)) {
      return null;
    }
    return {
      query,
      node: context.node,
      startOffset: atIndex,
      endOffset: context.offset
    };
  }

  function getAdjacentMention(selection, direction) {
    if (!selection || selection.rangeCount === 0) {
      return null;
    }
    const node = selection.focusNode;
    const offset = selection.focusOffset;
    if (!input || !input.contains(node)) {
      return null;
    }
    const parentElement = node.nodeType === Node.ELEMENT_NODE ? node : node.parentElement;
    const closestToken = parentElement?.closest?.(".mention-token");
    if (closestToken) {
      return closestToken;
    }
    if (node.nodeType === Node.TEXT_NODE) {
      const textLength = (node.textContent || "").length;
      if (direction === "backward" && offset === 0) {
        const prev = node.previousSibling || node.parentNode?.previousSibling;
        return isMentionToken(prev) ? prev : null;
      }
      if (direction === "forward" && offset === textLength) {
        const next = node.nextSibling || node.parentNode?.nextSibling;
        return isMentionToken(next) ? next : null;
      }
      return null;
    }
    if (node.nodeType === Node.ELEMENT_NODE) {
      const children = node.childNodes;
      if (direction === "backward") {
        const prev = children[offset - 1];
        return isMentionToken(prev) ? prev : null;
      }
      const next = children[offset];
      return isMentionToken(next) ? next : null;
    }
    return null;
  }

  function removeMentionToken(token) {
    if (!token || !token.parentNode) {
      return;
    }
    const parent = token.parentNode;
    const siblings = Array.from(parent.childNodes);
    const index = siblings.indexOf(token);
    const prevSibling = siblings[index - 1] || null;
    const nextSibling = siblings[index + 1] || null;
    token.remove();
    const selection = window.getSelection();
    if (!selection) {
      return;
    }
    selection.removeAllRanges();
    const range = document.createRange();
    const prevText = findLastTextNode(prevSibling);
    let nextText = findFirstTextNode(nextSibling);
    if (!nextText) {
      nextText = document.createTextNode("\u200B");
      if (nextSibling) {
        parent.insertBefore(nextText, nextSibling);
      } else {
        parent.appendChild(nextText);
      }
    }
    if (prevText) {
      range.setStart(prevText, prevText.textContent.length);
      range.collapse(true);
      selection.addRange(range);
      return;
    }
    range.setStart(nextText, Math.min(1, nextText.textContent.length));
    range.collapse(true);
    selection.addRange(range);
  }

  function updateAutocompletePosition() {
    if (!app || !input) {
      return;
    }
    const appRect = app.getBoundingClientRect();
    const inputRect = input.getBoundingClientRect();
    autocompleteEl.style.left = `${inputRect.left - appRect.left}px`;
    autocompleteEl.style.top = `${inputRect.top - appRect.top - 8}px`;
    autocompleteEl.style.width = `${inputRect.width}px`;
  }

  function closeAutocomplete() {
    autocompleteState.open = false;
    autocompleteState.items = [];
    autocompleteState.activeIndex = 0;
    autocompleteState.mention = null;
    autocompleteEl.classList.add("hidden");
    autocompleteEl.innerHTML = "";
  }

  function renderAutocomplete() {
    if (!autocompleteState.open || autocompleteState.items.length === 0) {
      closeAutocomplete();
      return;
    }
    autocompleteEl.innerHTML = "";
    autocompleteState.items.forEach((item, index) => {
      const option = document.createElement("button");
      option.type = "button";
      option.className = "autocomplete-item";
      option.textContent = item.name;
      option.addEventListener("mousedown", (event) => {
        event.preventDefault();
        selectAutocomplete(index);
      });
      option.addEventListener("mouseenter", () => {
        autocompleteState.activeIndex = index;
        updateAutocompleteActiveState();
      });
      autocompleteEl.appendChild(option);
    });
    updateAutocompleteActiveState();
    autocompleteEl.classList.remove("hidden");
    updateAutocompletePosition();
  }

  function updateAutocompleteActiveState() {
    const options = autocompleteEl.querySelectorAll(".autocomplete-item");
    options.forEach((option, index) => {
      option.classList.toggle("active", index === autocompleteState.activeIndex);
    });
    const active = options[autocompleteState.activeIndex];
    if (active && typeof active.scrollIntoView === "function") {
      active.scrollIntoView({ block: "nearest" });
    }
  }

  function openAutocomplete(items) {
    autocompleteState.items = items.slice(0, AUTOCOMPLETE_RESULT_LIMIT);
    autocompleteState.activeIndex = 0;
    autocompleteState.open = autocompleteState.items.length > 0;
    renderAutocomplete();
  }

  function moveAutocompleteSelection(delta) {
    const count = autocompleteState.items.length;
    if (!autocompleteState.open || count === 0) {
      return;
    }
    autocompleteState.activeIndex = (autocompleteState.activeIndex + delta + count) % count;
    if (autocompleteState.activeIndex < 0) {
      autocompleteState.activeIndex = 0;
    }
    renderAutocomplete();
  }

  function selectAutocomplete(index) {
    const item = autocompleteState.items[index];
    if (!item) {
      return;
    }
    const mention = autocompleteState.mention;
    if (!mention) {
      closeAutocomplete();
      return;
    }
    const range = document.createRange();
    range.setStart(mention.node, mention.startOffset);
    range.setEnd(mention.node, mention.endOffset);
    range.deleteContents();
    const token = document.createElement("span");
    token.className = "mention-token";
    token.setAttribute("contenteditable", "false");
    token.setAttribute("data-href", `ghidra://function/${item.address}`);
    token.textContent = item.name;
    range.insertNode(token);
    const spacer = document.createTextNode("\u200B ");
    token.after(spacer);
    const selection = window.getSelection();
    selection.removeAllRanges();
    const caretRange = document.createRange();
    caretRange.setStart(spacer, spacer.textContent.length);
    caretRange.collapse(true);
    selection.addRange(caretRange);
    input.focus();
    closeAutocomplete();
  }

  function scheduleAutocomplete() {
    if (!input) {
      return;
    }
    if (autocompleteTimer) {
      clearTimeout(autocompleteTimer);
    }
    autocompleteTimer = setTimeout(() => {
      normalizeInputContent();
      const mention = getMentionFromSelection();
      if (!mention || mention.query.length === 0) {
        closeAutocomplete();
        return;
      }
      autocompleteState.mention = mention;
      const requestId = `req-${Date.now()}-${autocompleteRequestCounter++}`;
      autocompleteState.pendingRequestId = requestId;
      dispatchBridgeEvent("copilot-autocomplete", { query: mention.query, requestId });
    }, AUTOCOMPLETE_DEBOUNCE_MS);
  }

  function applyAutocompleteState(nextAutocomplete) {
    if (!nextAutocomplete || !nextAutocomplete.requestId) {
      return;
    }
    if (nextAutocomplete.requestId !== autocompleteState.pendingRequestId) {
      return;
    }
    const currentMention = getMentionFromSelection();
    if (!currentMention || currentMention.query.length === 0) {
      closeAutocomplete();
      return;
    }
    const results = Array.isArray(nextAutocomplete.results) ? nextAutocomplete.results : [];
    if (results.length === 0) {
      closeAutocomplete();
      return;
    }
    openAutocomplete(results);
  }

  marked.setOptions({
    gfm: true,
    breaks: true,
    mangle: false,
    headerIds: false,
  });

  const PURIFY_CONFIG = {
    USE_PROFILES: { html: true },
    ALLOWED_URI_REGEXP: /^(?:(?:https?|mailto|tel|ghidra):|[^a-z]|[a-z+.\-]+(?:[^a-z+.\-:]|$))/i
  };

  function sanitize(html) {
    return DOMPurify.sanitize(html, PURIFY_CONFIG);
  }

  function linkifyGhidraUrls(text) {
    if (!text || !text.includes("ghidra://")) {
      return text;
    }
    const pattern = /ghidra:\/\/[^\s)]+/g;
    let result = "";
    let lastIndex = 0;
    let hasChanges = false;
    let match;
    while ((match = pattern.exec(text)) !== null) {
      const start = match.index;
      const end = pattern.lastIndex;
      const url = match[0];
      const prevChar = start > 0 ? text[start - 1] : "";
      if (prevChar === "(") {
        result += text.slice(lastIndex, end);
      } else {
        result += text.slice(lastIndex, start);
        result += `[${url}](${url})`;
        hasChanges = true;
      }
      lastIndex = end;
    }
    if (!hasChanges) {
      return text;
    }
    result += text.slice(lastIndex);
    return result;
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

    // When streaming, the text may not end with a newline - we're still receiving the current line.
    // Only consider a block complete when we've received the terminating newline.
    // Otherwise we'd render each token as a separate block (e.g. "H", "He", "Hello" each on its own line).
    const textEndsWithNewline = text.endsWith('\n');
    if (!textEndsWithNewline && blocks.length > 0) {
      const lastBlock = blocks[blocks.length - 1];
      if (lastBlock.end >= text.length) {
        blocks.pop();
      }
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

    let body = container;
    if (!message.fromUser) {
      const bodyEl = document.createElement("div");
      bodyEl.className = "message-body";
      const avatar = document.createElement("div");
      avatar.className = "assistant-avatar";
      const logo = document.createElement("img");
      logo.className = "avatar-logo";
      logo.src = "assets/Avatar.svg";
      logo.alt = "";
      avatar.appendChild(logo);
      bodyEl.appendChild(avatar);
      container.appendChild(bodyEl);
      body = bodyEl;
    }

    const bubble = document.createElement("div");
    bubble.className = "bubble";
    body.appendChild(bubble);

    return container;
  }

  function updateStreaming(messageEl, text) {
    const bubble = messageEl.querySelector(".bubble");
    
    // Initialize structure if needed — preserve any thinking section
    let renderedContent = bubble.querySelector(".rendered-content");
    let streamingContent = bubble.querySelector(".streaming-content");
    
    if (!renderedContent) {
      const thinkingSection = bubble.querySelector(".thinking-section");
      bubble.innerHTML = "";
      if (thinkingSection) {
        bubble.appendChild(thinkingSection);
      }
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
        const blockHTML = marked.parse(linkifyGhidraUrls(block.text));
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

    // Save the thinking section so it survives the innerHTML replacement
    const thinkingSection = bubble.querySelector(".thinking-section");

    const html = marked.parse(linkifyGhidraUrls(text));
    bubble.innerHTML = sanitize(html);

    if (thinkingSection) {
      bubble.insertBefore(thinkingSection, bubble.firstChild);
    }

    enhanceCodeBlocks(bubble);
    bubble.dataset.finalized = "true";
    messageEl.dataset.lastText = text;
    lastStreamingText = "";
    lastStreamingIndex = null;
  }

  let thinkingUserCollapsed = false;

  function ensureThinkingSection(bubble) {
    let section = bubble.querySelector(".thinking-section");
    if (section) {
      return section;
    }

    section = document.createElement("div");
    section.className = "thinking-section";

    const label = document.createElement("div");
    label.className = "thinking-label";
    const dot = document.createElement("span");
    dot.className = "thinking-dot";
    label.appendChild(dot);
    const labelText = document.createElement("span");
    labelText.className = "thinking-label-text";
    labelText.textContent = "Reasoning";
    label.appendChild(labelText);

    label.addEventListener("click", () => {
      const willCollapse = !section.classList.contains("collapsed");
      section.classList.toggle("collapsed");
      thinkingUserCollapsed = willCollapse;
    });

    section.appendChild(label);

    const content = document.createElement("div");
    content.className = "thinking-content";
    section.appendChild(content);

    bubble.insertBefore(section, bubble.firstChild);
    return section;
  }

  function updateThinkingInBubble(nextState) {
    const thinkingText = nextState.thinkingText || "";
    const panelOwnsProgress = shouldShowTodoSection(nextState) && !Boolean(nextState.todoMinimized);
    const inlineSubagentStream = !panelOwnsProgress && shouldInlineTaskProgress(nextState);
    const agentBusy = Boolean(nextState.loading || nextState.thinking);
    const hasReasoningContent = thinkingText.length > 0 && thinkingText !== "Reasoning...";

    const messages = chat.querySelectorAll(".message.assistant");
    const lastMsg = messages.length > 0 ? messages[messages.length - 1] : null;
    const bubble = lastMsg ? lastMsg.querySelector(".bubble") : null;

    if (!agentBusy) {
      if (bubble) {
        const section = bubble.querySelector(".thinking-section");
        if (section && !section.classList.contains("collapsed")) {
          section.classList.add("collapsed");
        }
      }
      return;
    }

    if (!bubble) {
      return;
    }

    if (!hasReasoningContent && !inlineSubagentStream) {
      return;
    }

    const section = ensureThinkingSection(bubble);

    if (!thinkingUserCollapsed) {
      section.classList.remove("collapsed");
    }

    const labelText = section.querySelector(".thinking-label-text");
    if (labelText) {
      labelText.textContent = inlineSubagentStream ? "Task progress" : "Reasoning";
    }

    const content = section.querySelector(".thinking-content");
    if (content) {
      let composed = thinkingText;
      if (inlineSubagentStream) {
        const agentType = (nextState.subAgentType && String(nextState.subAgentType).trim())
          ? String(nextState.subAgentType).trim()
          : "subagent";
        const streamText = nextState.subAgentStreamText != null ? String(nextState.subAgentStreamText) : "";
        const safeStream = streamText.trim().length > 0 ? streamText : "(waiting for output...)";
        composed = composed ? `${composed}\n\n` : "";
        composed += `Subagent stream (${agentType}):\n${safeStream}`;
      }
      content.textContent = composed;
    }
  }

  function renderError(error) {
    const existing = document.getElementById("floatingError");
    if (!error) {
      if (existing) {
        existing.classList.remove("is-visible");
      }
      return;
    }

    // Render error as a floating toast inside the dialog instead of a banner
    // that consumes layout space at the top of the chat feed.
    const banner = existing || document.createElement("div");
    banner.id = "floatingError";
    banner.className = "error-banner is-visible";
    banner.classList.remove("interactive");
    const errorText = String(error);
    const contactLabel = "Contact us";
    const contactIndex = errorText.indexOf(contactLabel);
    if (contactIndex >= 0) {
      const before = errorText.slice(0, contactIndex);
      const after = errorText.slice(contactIndex + contactLabel.length);
      banner.textContent = "";
      if (before) {
        banner.appendChild(document.createTextNode(before));
      }
      const contactButton = document.createElement("button");
      contactButton.type = "button";
      contactButton.className = "error-contact-link";
      contactButton.textContent = contactLabel;
      contactButton.addEventListener("click", (event) => {
        event.preventDefault();
        event.stopPropagation();
        dispatchBridgeEvent("copilot-open-contact-email", { email: SUPPORT_EMAIL });
      });
      banner.appendChild(contactButton);
      if (after) {
        banner.appendChild(document.createTextNode(after));
      }
      banner.classList.add("interactive");
    } else {
      banner.textContent = errorText;
    }
    if (!existing) {
      const container = app || document.body;
      container.appendChild(banner);
    }
    banner.classList.add("is-visible");
  }

  function renderPythonWarning(nextState) {
    if (!pythonWarningBadge) {
      return;
    }
    const visible = Boolean(nextState.pythonUnavailableWarningVisible);
    const warningText = nextState.pythonUnavailableWarningMessage
      || "Python runtime unavailable. Start via pyghidraRun.";
    pythonWarningBadge.classList.toggle("hidden", !visible);
    pythonWarningBadge.textContent = warningText;
    pythonWarningBadge.title = warningText;
  }

  function renderMessages(nextState) {
    const shouldClear =
      nextState.messages.length === 0 ||
      nextState.messages.length < state.messages.length;
    if (shouldClear) {
      const preservedEmptyState = emptyState;
      chat.innerHTML = "";
      if (preservedEmptyState) {
        chat.appendChild(preservedEmptyState);
      }
      renderedPositions.clear();
    }

    const displayError = nextState.serverBlocked
      ? (nextState.serverBlockedMessage || "Can't reach server")
      : (nextState.usageBlocked
        ? (nextState.usageBlockedMessage || "Usage limit expired. Upgrade or contact us to continue.")
        : nextState.error);
    renderError(displayError);

    syncActionButtons(nextState);

    if (emptyState) {
      emptyState.classList.toggle("hidden", nextState.messages.length > 0);
    }

    nextState.messages.forEach((message, index) => {
      let messageEl = chat.querySelector(`.message[data-index="${index}"]`);
      if (!messageEl) {
        messageEl = createBubble(message, index);
        chat.appendChild(messageEl);
      }

      if (message.fromUser) {
        const bubble = messageEl.querySelector(".bubble");
        const text = message.text || "";
        const html = marked.parse(linkifyGhidraUrls(text));
        bubble.innerHTML = sanitize(html);
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

    // Render thinking tokens inside the last assistant bubble
    updateThinkingInBubble(nextState);

    const showThinking = Boolean(nextState.loading || nextState.thinking);
    typingIndicator.classList.toggle("hidden", !showThinking);
    if (showThinking) {
      const label = typingIndicator.querySelector(".typing-label");
      if (label) {
        label.textContent = nextState.thinking ? "Reasoning..." : "Thinking...";
      }
    }
    if (statusPill) {
      const statusLabel = nextState.thinking
        ? "Reasoning..."
        : (showThinking ? "Thinking..." : "Ready");
      statusPill.textContent = statusLabel;
      statusPill.classList.toggle("busy", showThinking);
    }
    updatePlaceholder();
    scrollTranscriptToBottom();
  }

  function hasSubAgentStream(nextState) {
    return Boolean(
      (nextState.subAgentType && String(nextState.subAgentType).trim())
      || (nextState.subAgentStreamText && String(nextState.subAgentStreamText).trim())
    );
  }

  function collectTodoItems(nextState) {
    const ordered = [];
    const seen = new Set();
    const add = (value) => {
      if (value == null) {
        return;
      }
      const text = String(value).trim();
      if (!text || seen.has(text)) {
        return;
      }
      seen.add(text);
      ordered.push(text);
    };
    const todoSource = Array.isArray(nextState.todos) ? nextState.todos : [];
    const completedSource = Array.isArray(nextState.completedTodos) ? nextState.completedTodos : [];
    const failedSource = Array.isArray(nextState.failedTodos) ? nextState.failedTodos : [];
    todoSource.forEach(add);
    completedSource.forEach(add);
    failedSource.forEach(add);
    add(nextState.activeTodo);
    return ordered;
  }

  function hasToolHistory(nextState) {
    return Array.isArray(nextState.toolHistory) && nextState.toolHistory.length > 0;
  }

  function hasTaskProgressContent(nextState) {
    return collectTodoItems(nextState).length > 0 || hasSubAgentStream(nextState) || hasToolHistory(nextState);
  }

  function shouldInlineTaskProgress(nextState) {
    return Boolean(nextState.todoMinimized) && hasSubAgentStream(nextState);
  }

  function shouldShowTodoSection(nextState) {
    return hasTaskProgressContent(nextState) || taskProgressEverRendered;
  }

  function resolveTodoMinimized(nextState) {
    const incoming = Boolean(nextState.todoMinimized);
    if (pendingTodoMinimized === null) {
      return incoming;
    }
    if (!hasTaskProgressContent(nextState)) {
      pendingTodoMinimized = null;
      return incoming;
    }
    if (incoming === pendingTodoMinimized) {
      pendingTodoMinimized = null;
      return incoming;
    }
    return pendingTodoMinimized;
  }

  function renderTodos(nextState) {
    if (!todoSection || !todoList) {
      return;
    }
    const incomingTodos = collectTodoItems(nextState);
    const hasSubAgent = hasSubAgentStream(nextState);
    const incomingCompleted = Array.isArray(nextState.completedTodos)
      ? new Set(nextState.completedTodos.map((item) => String(item).trim()).filter(Boolean))
      : new Set();
    const incomingFailed = Array.isArray(nextState.failedTodos)
      ? new Set(nextState.failedTodos.map((item) => String(item).trim()).filter(Boolean))
      : new Set();
    const hasProgressContent = incomingTodos.length > 0 || hasSubAgent;
    const isConversationReset = Array.isArray(nextState.messages)
      && nextState.messages.length === 0
      && !hasProgressContent;

    if (isConversationReset) {
      taskProgressEverRendered = false;
      lastTaskProgressSnapshot = {
        todos: [],
        completed: [],
        failed: [],
        activeTodo: null,
      };
    }

    if (hasProgressContent) {
      taskProgressEverRendered = true;
      if (incomingTodos.length > 0) {
        lastTaskProgressSnapshot = {
          todos: incomingTodos.slice(),
          completed: Array.from(incomingCompleted),
          failed: Array.from(incomingFailed),
          activeTodo: nextState.activeTodo || null,
        };
      }
    }

    if (!shouldShowTodoSection(nextState)) {
      pendingTodoMinimized = null;
      todoList.innerHTML = "";
      todoSection.classList.add("hidden");
      return;
    }

    let todos = incomingTodos;
    let completed = incomingCompleted;
    let failed = incomingFailed;
    let activeTodo = nextState.activeTodo || null;
    if (todos.length === 0 && lastTaskProgressSnapshot.todos.length > 0) {
      todos = lastTaskProgressSnapshot.todos.slice();
      completed = new Set(lastTaskProgressSnapshot.completed);
      failed = new Set(lastTaskProgressSnapshot.failed);
      activeTodo = lastTaskProgressSnapshot.activeTodo;
    }

    todoList.innerHTML = "";
    todoSection.classList.remove("hidden");
    const minimized = Boolean(nextState.todoMinimized);
    todoSection.classList.toggle("minimized", minimized);
    if (todoToggle) {
      const label = todoToggle.querySelector(".todo-toggle-label");
      if (label) {
        label.textContent = minimized ? "Show" : "Hide";
      }
    }
    todoList.classList.toggle("hidden", todos.length === 0);
    todos.forEach((todo) => {
      const item = document.createElement("li");
      item.className = "todo-item";
      const text = document.createElement("span");
      text.className = "todo-text";
      text.textContent = todo;
      item.appendChild(text);
      if (failed.has(todo)) {
        item.classList.add("failed");
      } else if (completed.has(todo)) {
        item.classList.add("completed");
      }
      if (activeTodo && todo === activeTodo) {
        item.classList.add("active");
        const badge = document.createElement("span");
        badge.className = "todo-badge";
        badge.textContent = "Running";
        item.appendChild(badge);
      }
      todoList.appendChild(item);
    });
  }

  function renderTools(nextState) {
    if (!toolInfo || !toolHistoryEl) {
      return;
    }
    const history = Array.isArray(nextState.toolHistory) ? nextState.toolHistory : [];

    if (history.length === 0) {
      toolInfo.classList.add("hidden");
      toolHistoryEl.innerHTML = "";
      return;
    }

    toolInfo.classList.remove("hidden");
    toolHistoryEl.innerHTML = "";
    history.forEach((name) => {
      const chip = document.createElement("span");
      chip.className = "tool-chip";
      chip.textContent = name;
      toolHistoryEl.appendChild(chip);
    });
  }

  function renderSubAgent(nextState) {
    if (!subAgentBox || !subAgentTypeName || !subAgentStream) {
      return;
    }
    const agentType = nextState.subAgentType || "";
    const streamText = nextState.subAgentStreamText || "";

    if (!agentType && !streamText) {
      subAgentBox.classList.add("hidden");
      subAgentTypeName.textContent = "";
      subAgentStream.textContent = "";
      return;
    }

    subAgentBox.classList.remove("hidden");
    subAgentTypeName.textContent = agentType || "general-purpose";
    subAgentStream.textContent = streamText;
    subAgentStream.scrollTop = subAgentStream.scrollHeight;
  }

  function setState(nextState) {
    logToHost("CopilotUI.setState invoked");
    const prevMessages = Array.isArray(state.messages) ? state.messages : [];
    const backendBusy = Boolean(nextState.loading || nextState.thinking);
    const assistantResponseAvailable = hasAssistantResponse(prevMessages, nextState.messages);
    if (backendBusy || nextState.error || assistantResponseAvailable) {
      pendingSend = false;
    }
    state.messages = nextState.messages || [];
    state.loading = Boolean(nextState.loading);
    state.error = nextState.error || null;
    state.thinking = Boolean(nextState.thinking);
    state.thinkingText = nextState.thinkingText || null;
    state.autocomplete = nextState.autocomplete || null;
    state.usageBlocked = Boolean(nextState.usageBlocked);
    state.usageBlockedMessage = nextState.usageBlockedMessage || null;
    state.serverBlocked = Boolean(nextState.serverBlocked);
    state.serverBlockedMessage = nextState.serverBlockedMessage || null;
    state.pythonUnavailableWarningVisible = Boolean(nextState.pythonUnavailableWarningVisible);
    state.pythonUnavailableWarningMessage = nextState.pythonUnavailableWarningMessage || null;
    state.todos = Array.isArray(nextState.todos) ? nextState.todos : [];
    state.activeTodo = nextState.activeTodo || null;
    state.toolHistory = Array.isArray(nextState.toolHistory) ? nextState.toolHistory : [];
    state.completedTodos = Array.isArray(nextState.completedTodos) ? nextState.completedTodos : [];
    state.failedTodos = Array.isArray(nextState.failedTodos) ? nextState.failedTodos : [];
    state.todoMinimized = resolveTodoMinimized(nextState);
    state.subAgentType = nextState.subAgentType || null;
    state.subAgentStreamText = nextState.subAgentStreamText || null;
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
    renderMessages(state);
    renderPythonWarning(state);
    renderTodos(state);
    renderTools(state);
    renderSubAgent(state);
    applyAutocompleteState(state.autocomplete);
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

  function applyStreamingChunk(chunk) {
    if (!chunk) {
      return;
    }
    if (!Array.isArray(state.messages) || state.messages.length === 0) {
      return;
    }
    const index = state.messages.length - 1;
    const target = state.messages[index];
    if (!target || target.fromUser) {
      return;
    }
    target.text = (target.text || "") + chunk;
    let messageEl = chat.querySelector(`.message[data-index="${index}"]`);
    if (!messageEl) {
      renderMessages(state);
      messageEl = chat.querySelector(`.message[data-index="${index}"]`);
      if (!messageEl) {
        return;
      }
    }
    updateStreaming(messageEl, target.text || "");
    const showThinking = Boolean(state.loading || state.thinking);
    typingIndicator.classList.toggle("hidden", !showThinking);
    scrollTranscriptToBottom();
  }

  function applyStreamFromBridge() {
    if (!bridgeEl) {
      return;
    }
    const raw = bridgeEl.dataset.stream;
    if (!raw) {
      return;
    }
    try {
      const parsed = JSON.parse(raw);
      if (parsed && typeof parsed.chunk === "string") {
        applyStreamingChunk(parsed.chunk);
      }
    } catch (e) {
      logToHost("CopilotUI failed to parse bridge stream: " + e.message);
    }
  }

  if (bridgeEl) {
    const observer = new MutationObserver((mutations) => {
      mutations.forEach((mutation) => {
        if (mutation.type === "attributes") {
          if (mutation.attributeName === "data-state") {
            applyStateFromBridge();
          } else if (mutation.attributeName === "data-stream") {
            applyStreamFromBridge();
          }
        }
      });
    });
    observer.observe(bridgeEl, { attributes: true, attributeFilter: ["data-state", "data-stream"] });
    applyStateFromBridge();
  }

  function sendMessage() {
    if (state.usageBlocked || state.serverBlocked || isBusyState(state)) {
      return;
    }
    const text = serializeInputToMarkdown().trim();
    if (!text) {
      return;
    }
    userScrolledUp = false;
    thinkingUserCollapsed = false;
    resetTaskProgressUiState();
    renderTodos(state);
    renderTools(state);
    renderSubAgent(state);
    pendingSend = true;
    syncActionButtons(state);
    dispatchBridgeEvent("copilot-send", { message: text });
    input.innerHTML = "";
    closeAutocomplete();
  }

  dispatchBridgeEvent("copilot-loaded", {});
  syncActionButtons(state);
  sendBtn.addEventListener("click", sendMessage);
  stopBtn.addEventListener("click", () => {
    dispatchBridgeEvent("copilot-stop", {});
  });
  if (closeBtn) {
    closeBtn.addEventListener("click", () => {
      dispatchBridgeEvent("copilot-close", {});
    });
  }
  if (clearBtn) {
    clearBtn.addEventListener("click", () => {
      resetTaskProgressUiState();
      renderTodos(state);
      renderTools(state);
      renderSubAgent(state);
      userScrolledUp = false;
      thinkingUserCollapsed = false;
      updatePlaceholder();
      dispatchBridgeEvent("copilot-clear", {});
    });
  }
  if (todoToggle) {
    todoToggle.addEventListener("click", () => {
      const nextMinimized = !Boolean(state.todoMinimized);
      pendingTodoMinimized = nextMinimized;
      state.todoMinimized = nextMinimized;
      renderTodos(state);
      dispatchBridgeEvent("copilot-toggle-todos", { minimized: nextMinimized });
    });
  }
  if (chat) {
    chat.addEventListener("click", handleLinkClick);
  }
  if (emptyState) {
    emptyState.addEventListener("click", (event) => {
      const target = event.target?.closest?.(".empty-chip");
      if (!target) {
        return;
      }
      const suggestion = target.dataset.suggestion;
      if (!suggestion) {
        return;
      }
      event.preventDefault();
      setInputText(suggestion);
    });
  }

  input.addEventListener("keydown", (event) => {
    if (event.defaultPrevented) {
      return;
    }
    if (autocompleteState.open) {
      if (event.key === "ArrowDown") {
        event.preventDefault();
        moveAutocompleteSelection(1);
        return;
      }
      if (event.key === "ArrowUp") {
        event.preventDefault();
        moveAutocompleteSelection(-1);
        return;
      }
      if (event.key === "Enter" || event.key === "Tab") {
        event.preventDefault();
        selectAutocomplete(autocompleteState.activeIndex);
        return;
      }
      if (event.key === "Escape") {
        event.preventDefault();
        closeAutocomplete();
        return;
      }
    }
    if (isPlainEnter(event)) {
      event.preventDefault();
      sendMessage();
    }
  });

  input.addEventListener("input", () => {
    normalizeInputContent();
    scheduleAutocomplete();
  });
  input.addEventListener("click", () => {
    if (!autocompleteState.open) {
      return;
    }
    const mention = getMentionFromSelection();
    if (!mention) {
      closeAutocomplete();
    }
  });
  input.addEventListener("keyup", (event) => {
    if (!autocompleteState.open) {
      return;
    }
    if (event.key.startsWith("Arrow") || event.key === "Home" || event.key === "End") {
      const mention = getMentionFromSelection();
      if (!mention) {
        closeAutocomplete();
      }
    }
  });
  input.addEventListener("blur", () => {
    setTimeout(() => {
      if (document.activeElement === input) {
        return;
      }
      closeAutocomplete();
    }, 100);
  });

  input.addEventListener("click", (event) => {
    const mentionToken = event.target?.closest?.(".mention-token");
    const href = mentionToken?.getAttribute("data-href")
      || event.target?.closest?.("a")?.getAttribute?.("href");
    if (href && href.startsWith("ghidra://")) {
      event.preventDefault();
      event.stopPropagation();
      dispatchBridgeEvent("copilot-navigate", { url: href });
    }
  });

  document.addEventListener("keydown", (event) => {
    if (event.defaultPrevented) {
      return;
    }
    if (autocompleteState.open) {
      if (event.key === "Enter" || event.key === "Tab") {
        event.preventDefault();
        event.stopImmediatePropagation();
        selectAutocomplete(autocompleteState.activeIndex);
        return;
      }
      if (event.key === "ArrowDown") {
        event.preventDefault();
        moveAutocompleteSelection(1);
        return;
      }
      if (event.key === "ArrowUp") {
        event.preventDefault();
        moveAutocompleteSelection(-1);
        return;
      }
      if (event.key === "Escape") {
        event.preventDefault();
        closeAutocomplete();
        return;
      }
    }
    if (isInputFocused() && isPlainEnter(event)) {
      event.preventDefault();
      sendMessage();
    }
  }, true);

  window.addEventListener("keydown", (event) => {
    if (!autocompleteState.open) {
      return;
    }
    if (event.key === "Tab") {
      event.preventDefault();
      event.stopImmediatePropagation();
      selectAutocomplete(autocompleteState.activeIndex);
    }
  }, true);

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
    isAutocompleteOpen: () => autocompleteState.open,
    acceptAutocomplete: () => {
      if (autocompleteState.open) {
        selectAutocomplete(autocompleteState.activeIndex);
      }
    },
    moveAutocompleteSelection: (delta) => {
      if (autocompleteState.open) {
        moveAutocompleteSelection(delta);
      }
    },
  };
})();
