const API_URL = 'http://localhost:8000/analyze';
const MIN_TEXT_LENGTH = 20;
const API_TIMEOUT_MS = 5000;
const PAGE_LOAD_DEBOUNCE_MS = 2000;
const MAX_API_TEXT_LENGTH = 5000;

let isProtectionActive = false;
let debounceTimer = null;
let loadingEl = null;
const highlights = [];
const pageLoadTs = Date.now();

console.log('🛡️ SurakshaAI Shield content script loaded');

function isElementVisible(element) {
  if (!element || !(element instanceof Element)) return false;
  const style = window.getComputedStyle(element);
  if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') {
    return false;
  }
  if (element.hasAttribute('hidden') || element.getAttribute('aria-hidden') === 'true') {
    return false;
  }
  return true;
}

function extractVisibleTextBlocks() {
  if (!document.body) return [];

  const blocks = [];
  const walker = document.createTreeWalker(
    document.body,
    NodeFilter.SHOW_TEXT,
    {
      acceptNode: (node) => {
        const parent = node.parentElement;
        if (!parent) return NodeFilter.FILTER_REJECT;
        if (['SCRIPT', 'STYLE', 'NOSCRIPT', 'IFRAME'].includes(parent.tagName)) {
          return NodeFilter.FILTER_REJECT;
        }

        let el = parent;
        while (el && el !== document.body) {
          if (!isElementVisible(el)) return NodeFilter.FILTER_REJECT;
          el = el.parentElement;
        }

        const text = node.textContent?.replace(/\s+/g, ' ').trim() || '';
        if (!text) return NodeFilter.FILTER_REJECT;
        return NodeFilter.FILTER_ACCEPT;
      }
    }
  );

  let node;
  while ((node = walker.nextNode())) {
    const cleaned = node.textContent?.replace(/\s+/g, ' ').trim() || '';
    if (cleaned) {
      blocks.push({ node, text: cleaned });
    }
  }

  return blocks;
}

function buildTextBatches(blocks, maxChars = MAX_API_TEXT_LENGTH) {
  const batches = [];
  let current = [];
  let currentLen = 0;

  blocks.forEach((block) => {
    const text = block.text;
    if (!text) return;

    const safeText = text.length > maxChars ? text.slice(0, maxChars) : text;

    if (currentLen > 0 && currentLen + safeText.length + 1 > maxChars) {
      batches.push({ blocks: current, text: current.map((item) => item.text).join('\n') });
      current = [];
      currentLen = 0;
    }

    current.push({ node: block.node, text: safeText });
    currentLen += safeText.length + 1;
  });

  if (current.length > 0) {
    batches.push({ blocks: current, text: current.map((item) => item.text).join('\n') });
  }

  return batches;
}

function showLoadingIndicator(message = 'Scanning page...') {
  hideLoadingIndicator();
  loadingEl = document.createElement('div');
  loadingEl.className = 'surakshaai-loading';
  loadingEl.textContent = message;
  document.body.appendChild(loadingEl);
}

function hideLoadingIndicator() {
  if (loadingEl) {
    loadingEl.remove();
    loadingEl = null;
  }
}

function showToast(message) {
  const toast = document.createElement('div');
  toast.className = 'surakshaai-toast';
  toast.textContent = message;
  document.body.appendChild(toast);
  setTimeout(() => toast.remove(), 3500);
}

async function analyzeText(text) {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), API_TIMEOUT_MS);

  try {
    const response = await fetch(API_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text }),
      signal: controller.signal
    });

    if (!response.ok) {
      if (response.status === 422) {
        throw new Error('Page content too large for one request');
      }
      throw new Error(`API returned ${response.status}`);
    }

    return await response.json();
  } catch (error) {
    console.error('❌ Analyze API error:', error);

    if (error.name === 'AbortError') {
      throw new Error('Request timeout after 5 seconds');
    }

    if (error instanceof TypeError) {
      throw new Error('Backend not available');
    }

    throw error;
  } finally {
    clearTimeout(timeoutId);
  }
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function getRiskClass(risk) {
  if (risk > 70) return 'risk-high';
  if (risk >= 40) return 'risk-medium';
  return 'risk-low';
}

function showTooltip(x, y, threat) {
  document.querySelectorAll('.surakshaai-tooltip').forEach((tip) => tip.remove());

  const tooltip = document.createElement('div');
  tooltip.className = 'surakshaai-tooltip';
  const risk = Number(threat.risk || 0);

  tooltip.innerHTML = `
    <div class="risk-badge ${getRiskClass(risk)}">Risk: ${risk}%</div>
    <div><strong>Category:</strong> ${threat.category || 'unknown'}</div>
    <div style="margin-top:8px;">${threat.explanation || 'No explanation provided.'}</div>
  `;

  document.body.appendChild(tooltip);
  tooltip.style.left = `${Math.min(x + 8, window.innerWidth - tooltip.offsetWidth - 12)}px`;
  tooltip.style.top = `${Math.min(y + 8, window.innerHeight - tooltip.offsetHeight - 12)}px`;

  setTimeout(() => {
    if (tooltip.isConnected) tooltip.remove();
  }, 6000);

  document.addEventListener(
    'click',
    () => {
      if (tooltip.isConnected) tooltip.remove();
    },
    { once: true }
  );
}

function applyHighlightsToTextNode(textNode, nodeThreats) {
  if (!textNode?.parentNode || !nodeThreats.length) return;

  const sourceText = textNode.textContent;
  const phraseMap = new Map();

  nodeThreats.forEach((threat) => {
    if (!threat.phrase) return;
    phraseMap.set(threat.phrase.toLowerCase(), threat);
  });

  const phrases = [...phraseMap.keys()].sort((a, b) => b.length - a.length);
  if (!phrases.length) return;

  const regex = new RegExp(`(${phrases.map(escapeRegExp).join('|')})`, 'ig');
  const parts = sourceText.split(regex);
  if (parts.length <= 1) return;

  const fragment = document.createDocumentFragment();

  parts.forEach((part) => {
    const matchKey = part.toLowerCase();
    const threat = phraseMap.get(matchKey);

    if (!threat) {
      fragment.appendChild(document.createTextNode(part));
      return;
    }

    const span = document.createElement('span');
    span.className = 'surakshaai-highlight';
    span.textContent = part;
    span.dataset.risk = String(threat.risk ?? 0);
    span.dataset.category = threat.category || 'unknown';
    span.dataset.explanation = threat.explanation || '';
    span.dataset.phrase = threat.phrase || part;

    span.addEventListener('click', (event) => {
      event.stopPropagation();
      showTooltip(event.clientX, event.clientY, threat);
    });

    highlights.push(span);
    fragment.appendChild(span);
  });

  textNode.parentNode.replaceChild(fragment, textNode);
}

function clearHighlights() {
  highlights.forEach((span) => {
    const parent = span.parentNode;
    if (!parent) return;
    span.replaceWith(document.createTextNode(span.textContent || ''));
    parent.normalize();
  });
  highlights.length = 0;

  document.querySelectorAll('.surakshaai-tooltip, .surakshaai-toast').forEach((node) => node.remove());
  hideLoadingIndicator();
}

function mergeThreats(allThreats, incomingThreats) {
  incomingThreats.forEach((threat) => {
    const key = `${(threat.phrase || '').toLowerCase()}|${threat.category || ''}`;
    if (!key.trim() || key === '|') return;
    if (!allThreats.some((saved) => `${(saved.phrase || '').toLowerCase()}|${saved.category || ''}` === key)) {
      allThreats.push(threat);
    }
  });
}

async function scanPage() {
  if (!isProtectionActive) {
    return { ok: false, threats: 0, message: 'Protection is inactive' };
  }

  clearHighlights();
  showLoadingIndicator('Analyzing page content...');

  try {
    const blocks = extractVisibleTextBlocks();
    const fullText = blocks.map((b) => b.text).join('\n');

    if (fullText.trim().length < MIN_TEXT_LENGTH) {
      hideLoadingIndicator();
      return { ok: true, threats: 0, message: 'Text too short. Skipping scan.' };
    }

    const batches = buildTextBatches(blocks, MAX_API_TEXT_LENGTH);
    const allThreats = [];

    for (let i = 0; i < batches.length; i += 1) {
      showLoadingIndicator(`Analyzing page content... (${i + 1}/${batches.length})`);
      const result = await analyzeText(batches[i].text);
      const threats = Array.isArray(result?.threats) ? result.threats : [];
      mergeThreats(allThreats, threats);
    }

    const threatsByNode = new Map();
    blocks.forEach((block) => {
      const relatedThreats = allThreats.filter((threat) => {
        const phrase = threat.phrase?.toLowerCase();
        return phrase && block.text.toLowerCase().includes(phrase);
      });

      if (relatedThreats.length) {
        threatsByNode.set(block.node, relatedThreats);
      }
    });

    threatsByNode.forEach((nodeThreats, node) => {
      applyHighlightsToTextNode(node, nodeThreats);
    });

    hideLoadingIndicator();
    return {
      ok: true,
      threats: allThreats.length,
      message: `Detected ${allThreats.length} threat(s) across ${batches.length} page chunk(s).`
    };
  } catch (error) {
    hideLoadingIndicator();

    const friendlyMessage =
      error.message === 'Backend not available'
        ? 'Backend not available'
        : error.message.includes('timeout')
          ? 'Request timed out. Try again.'
          : error.message.includes('too large')
            ? 'Page is very large. Scan partially completed.'
            : 'Scan failed. Please try again.';

    showToast(friendlyMessage);
    console.error('❌ Scan failed:', error);
    return { ok: false, threats: 0, message: friendlyMessage };
  }
}

function scheduleScan() {
  if (debounceTimer) clearTimeout(debounceTimer);
  const elapsed = Date.now() - pageLoadTs;
  const waitMs = Math.max(PAGE_LOAD_DEBOUNCE_MS - elapsed, 0);

  return new Promise((resolve) => {
    debounceTimer = setTimeout(async () => {
      debounceTimer = null;
      const result = await scanPage();
      resolve(result);
    }, waitMs);
  });
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'START_SCAN') {
    isProtectionActive = true;
    scheduleScan().then((result) => sendResponse(result));
    return true;
  }

  if (message.action === 'STOP_SCAN') {
    isProtectionActive = false;
    if (debounceTimer) {
      clearTimeout(debounceTimer);
      debounceTimer = null;
    }
    clearHighlights();
    sendResponse({ ok: true, threats: 0, message: 'Protection deactivated' });
  }

  return false;
});
