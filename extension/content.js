const API_URL = 'http://localhost:8000/analyze';
const MAX_TEXT_LENGTH = 4500; // API limit is 5000, leave buffer
const highlights = [];
let isProtectionActive = false;
let loadingOverlay = null;

console.log('SurakshaAI Shield loaded on this page');

// ============ LOADING INDICATOR ============
function showLoading() {
  removeLoading();
  loadingOverlay = document.createElement('div');
  loadingOverlay.className = 'surakshaai-loading';
  loadingOverlay.innerHTML = `
    <div class="surakshaai-loading-spinner"></div>
    <div style="margin-top:10px;font-size:14px;">SurakshaAI scanning page...</div>
  `;
  document.body.appendChild(loadingOverlay);
}

function removeLoading() {
  if (loadingOverlay) {
    loadingOverlay.remove();
    loadingOverlay = null;
  }
  document.querySelectorAll('.surakshaai-loading').forEach(el => el.remove());
}

// ============ EXTRACT TEXT FROM PAGE ============
function extractTextBlocks() {
  console.log('Extracting text from page...');
  const blocks = [];

  const walker = document.createTreeWalker(
    document.body,
    NodeFilter.SHOW_TEXT,
    {
      acceptNode: (node) => {
        const parent = node.parentElement;
        if (!parent) return NodeFilter.FILTER_REJECT;

        // Skip script, style, noscript tags
        const tag = parent.tagName;
        if (['SCRIPT', 'STYLE', 'NOSCRIPT', 'SVG', 'PATH'].includes(tag)) {
          return NodeFilter.FILTER_REJECT;
        }

        // Skip hidden elements
        const style = window.getComputedStyle(parent);
        if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') {
          return NodeFilter.FILTER_REJECT;
        }

        // Skip extension's own elements
        if (parent.closest('.surakshaai-loading, .surakshaai-tooltip, .surakshaai-highlight')) {
          return NodeFilter.FILTER_REJECT;
        }

        const text = node.textContent.trim();
        if (text.length < 5) return NodeFilter.FILTER_REJECT;

        return NodeFilter.FILTER_ACCEPT;
      }
    }
  );

  let node;
  while (node = walker.nextNode()) {
    blocks.push({
      node: node,
      text: node.textContent.trim()
    });
  }

  console.log(`Found ${blocks.length} text blocks`);
  return blocks;
}

// ============ CALL BACKEND API ============
async function analyzeText(text) {
  // Truncate if too long for API
  const truncated = text.length > MAX_TEXT_LENGTH ? text.substring(0, MAX_TEXT_LENGTH) : text;

  console.log(`Sending ${truncated.length} chars to backend for analysis...`);

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 5000);

    const response = await fetch(API_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ text: truncated }),
      signal: controller.signal
    });

    clearTimeout(timeoutId);

    if (!response.ok) {
      const errorText = await response.text().catch(() => '');
      console.error(`API returned ${response.status}: ${errorText}`);
      throw new Error(`API returned ${response.status}`);
    }

    const result = await response.json();
    console.log('Analysis complete:', result);
    return result;

  } catch (error) {
    if (error.name === 'AbortError') {
      console.error('API timeout - backend took too long');
      return { error: 'timeout', overall_risk: 0, threats: [], severity: 'low' };
    }
    if (error.message.includes('Failed to fetch') || error.message.includes('NetworkError')) {
      console.error('Backend not available');
      return { error: 'unavailable', overall_risk: 0, threats: [], severity: 'low' };
    }
    console.error('API call failed:', error);
    return { error: error.message, overall_risk: 0, threats: [], severity: 'low' };
  }
}

// ============ ANALYZE IN CHUNKS ============
async function analyzeAllText(blocks) {
  // Group text into chunks that fit within API limit
  const chunks = [];
  let currentChunk = '';
  const blockMapping = []; // tracks which blocks are in which chunk

  for (let i = 0; i < blocks.length; i++) {
    const blockText = blocks[i].text;
    if (currentChunk.length + blockText.length + 2 > MAX_TEXT_LENGTH) {
      if (currentChunk.length > 0) {
        chunks.push(currentChunk);
      }
      currentChunk = blockText.substring(0, MAX_TEXT_LENGTH);
    } else {
      currentChunk += (currentChunk ? '\n\n' : '') + blockText;
    }
  }
  if (currentChunk.length > 0) {
    chunks.push(currentChunk);
  }

  console.log(`Split into ${chunks.length} chunk(s) for analysis`);

  // Analyze each chunk
  const allThreats = [];
  let maxRisk = 0;
  let lastSeverity = 'low';
  let hasError = null;

  for (const chunk of chunks) {
    if (chunk.trim().length < 20) {
      console.log('Skipping chunk - too short');
      continue;
    }

    const result = await analyzeText(chunk);

    if (result.error) {
      hasError = result.error;
      continue;
    }

    if (result.threats && result.threats.length > 0) {
      allThreats.push(...result.threats);
    }
    if (result.overall_risk > maxRisk) {
      maxRisk = result.overall_risk;
      lastSeverity = result.severity;
    }
  }

  return {
    overall_risk: maxRisk,
    severity: lastSeverity,
    threats: allThreats,
    error: allThreats.length === 0 ? hasError : null
  };
}

// ============ HIGHLIGHT DANGEROUS TEXT ============
function highlightText(textNode, phrase, risk, explanation, category) {
  const text = textNode.textContent;
  const lowerText = text.toLowerCase();
  const lowerPhrase = phrase.toLowerCase();
  const index = lowerText.indexOf(lowerPhrase);

  if (index === -1) return;

  console.log(`Highlighting: "${phrase}" with risk ${risk}%`);

  try {
    const range = document.createRange();
    range.setStart(textNode, index);
    range.setEnd(textNode, index + phrase.length);

    const span = document.createElement('span');
    span.className = 'surakshaai-highlight';
    span.dataset.risk = risk;
    span.dataset.explanation = explanation || '';
    span.dataset.phrase = phrase;
    span.dataset.category = category || '';

    span.addEventListener('click', (e) => {
      e.stopPropagation();
      showTooltip(e.clientX, e.clientY, risk, explanation, category, phrase);
    });

    range.surroundContents(span);
    highlights.push(span);

  } catch (e) {
    console.warn('Could not highlight phrase:', phrase, e);
  }
}

// ============ SHOW TOOLTIP ============
function showTooltip(x, y, risk, explanation, category, phrase) {
  document.querySelectorAll('.surakshaai-tooltip').forEach(t => t.remove());

  const tooltip = document.createElement('div');
  tooltip.className = 'surakshaai-tooltip';

  const riskLevel = risk > 70 ? 'high' : risk > 40 ? 'medium' : 'low';
  const riskText = risk > 70 ? 'High Risk' : risk > 40 ? 'Medium Risk' : 'Low Risk';
  const categoryLabel = category ? category.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase()) : '';

  tooltip.innerHTML = `
    <div class="surakshaai-tooltip-header">
      <div class="risk-badge risk-${riskLevel}">${riskText}: ${risk}%</div>
      ${categoryLabel ? `<div class="surakshaai-category">${categoryLabel}</div>` : ''}
    </div>
    <div class="surakshaai-phrase">"${phrase}"</div>
    <div class="surakshaai-explanation">${explanation || 'Potential phishing indicator detected.'}</div>
  `;

  document.body.appendChild(tooltip);

  // Position tooltip - keep within viewport
  const rect = tooltip.getBoundingClientRect();
  const left = Math.min(x, window.innerWidth - rect.width - 10);
  const top = y + 15 + rect.height > window.innerHeight ? y - rect.height - 10 : y + 15;
  tooltip.style.left = `${Math.max(10, left)}px`;
  tooltip.style.top = `${Math.max(10, top)}px`;

  setTimeout(() => tooltip.remove(), 8000);
  setTimeout(() => {
    document.addEventListener('click', () => tooltip.remove(), { once: true });
  }, 100);
}

// ============ NOTIFY POPUP ============
function notifyPopup(data) {
  try {
    chrome.runtime.sendMessage(data);
  } catch (e) {
    // Popup may be closed, that's fine
    console.log('Could not send message to popup (popup may be closed)');
  }
}

// ============ MAIN SCAN FUNCTION ============
async function scanPage() {
  if (!isProtectionActive) return;

  console.log('Starting page scan...');
  showLoading();
  notifyPopup({ action: 'SCAN_STARTED' });

  // Debounce: wait for page to settle
  await new Promise(resolve => setTimeout(resolve, 2000));

  if (!isProtectionActive) {
    removeLoading();
    return;
  }

  // Extract all text from page
  const blocks = extractTextBlocks();

  if (blocks.length === 0) {
    console.log('No text found on page');
    removeLoading();
    notifyPopup({ action: 'SCAN_COMPLETE', threats: 0, error: 'No text found on page' });
    return;
  }

  const fullText = blocks.map(b => b.text).join('\n\n');
  console.log(`Total text length: ${fullText.length} chars`);

  if (fullText.trim().length < 20) {
    console.log('Text too short to scan');
    removeLoading();
    notifyPopup({ action: 'SCAN_COMPLETE', threats: 0, error: 'Text too short to analyze' });
    return;
  }

  // Analyze with backend
  const result = await analyzeAllText(blocks);

  removeLoading();

  if (!isProtectionActive) return;

  // Handle errors
  if (result.error) {
    let errorMsg = 'Analysis failed';
    if (result.error === 'timeout') {
      errorMsg = 'Backend took too long (>5s). Please try again.';
    } else if (result.error === 'unavailable') {
      errorMsg = 'Backend not available. Make sure the server is running at localhost:8000';
    }
    console.warn('Scan error:', errorMsg);
    notifyPopup({ action: 'SCAN_COMPLETE', threats: 0, error: errorMsg, overall_risk: 0, severity: 'low' });
    return;
  }

  // Highlight threats
  if (result.threats && result.threats.length > 0) {
    console.log(`Found ${result.threats.length} threats!`);

    result.threats.forEach(threat => {
      blocks.forEach(block => {
        if (block.node.parentNode && block.text.toLowerCase().includes(threat.phrase.toLowerCase())) {
          highlightText(
            block.node,
            threat.phrase,
            threat.risk,
            threat.explanation,
            threat.category
          );
        }
      });
    });

    notifyPopup({
      action: 'SCAN_COMPLETE',
      threats: result.threats.length,
      overall_risk: result.overall_risk,
      severity: result.severity,
      error: null
    });
  } else {
    console.log('No threats detected on this page');
    notifyPopup({
      action: 'SCAN_COMPLETE',
      threats: 0,
      overall_risk: result.overall_risk || 0,
      severity: result.severity || 'low',
      error: null
    });
  }
}

// ============ CLEAR HIGHLIGHTS ============
function clearHighlights() {
  console.log('Clearing all highlights...');
  highlights.forEach(span => {
    const parent = span.parentNode;
    if (parent) {
      parent.replaceChild(document.createTextNode(span.textContent), span);
      parent.normalize(); // merge adjacent text nodes
    }
  });
  highlights.length = 0;

  document.querySelectorAll('.surakshaai-tooltip').forEach(t => t.remove());
  removeLoading();
}

// ============ MESSAGE HANDLER ============
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  console.log('Received message:', message);

  if (message.action === 'START_SCAN') {
    isProtectionActive = true;
    chrome.storage.local.set({ isActive: true });
    console.log('Protection activated - starting scan');
    scanPage();
    sendResponse({ status: 'scanning' });
  } else if (message.action === 'STOP_SCAN') {
    isProtectionActive = false;
    chrome.storage.local.set({ isActive: false });
    console.log('Protection deactivated');
    clearHighlights();
    sendResponse({ status: 'stopped' });
  } else if (message.action === 'GET_STATUS') {
    sendResponse({ isActive: isProtectionActive, threats: highlights.length });
  }

  return true; // keep message channel open for async
});

// ============ INITIALIZATION ============
console.log('SurakshaAI Shield ready!');
