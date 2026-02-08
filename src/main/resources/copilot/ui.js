(() => {
  const chat = document.getElementById("chat");
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

  const state = {
    messages: [],
    loading: false,
    error: null,
    thinking: false,
    thinkingText: null,
    autocomplete: null,
  };

  let lastStreamingIndex = null;
  let lastStreamingText = "";

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
    
    // Render final markdown
    const html = marked.parse(linkifyGhidraUrls(text));
    bubble.innerHTML = sanitize(html);
    enhanceCodeBlocks(bubble);
    bubble.dataset.finalized = "true";
    messageEl.dataset.lastText = text;
    lastStreamingText = "";
    lastStreamingIndex = null;
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

    renderError(nextState.error);

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

    const showThinking = Boolean(nextState.loading || nextState.thinking);
    typingIndicator.classList.toggle("hidden", !showThinking);
    if (showThinking) {
      const label = typingIndicator.querySelector(".typing-label");
      if (label) {
        label.textContent = nextState.thinkingText || "Thinking...";
      }
    }
    if (statusPill) {
      const label = nextState.thinkingText || (showThinking ? "Thinking..." : "Ready");
      statusPill.textContent = label;
      statusPill.classList.toggle("busy", showThinking);
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
    state.autocomplete = nextState.autocomplete || null;
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
    const text = serializeInputToMarkdown().trim();
    if (!text) {
      return;
    }
    dispatchBridgeEvent("copilot-send", { message: text });
    input.innerHTML = "";
    closeAutocomplete();
  }

  dispatchBridgeEvent("copilot-loaded", {});
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
      dispatchBridgeEvent("copilot-clear", {});
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
    if (event.key === "Enter" && !event.shiftKey) {
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
    if (!autocompleteState.open || event.defaultPrevented) {
      return;
    }
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
