const API_URL = 'http://localhost:8000/analyze_text';
let isProtectionActive = false;

const NOISE_PATTERNS = [
  /-refreshed/i,
  /^ic-/i,
  /^wds-/i,
  /^default-(group|contact)/i,
  /^video-call/i,
  /^document-/i,
  /^chat-/i,
  /^search-/i,
  /^community-/i,
];

const SUSPICIOUS_HINTS = /(otp|password|pin|cvv|kyc|verify|account\s*(blocked|suspend|freeze)|click here|urgent|immediately|bank|sbi|hdfc|icici|rbi|http:\/\/|https:\/\/|तुरंत|ओटीपी|पासवर्ड|உடனே|ஒடிபி|এখনই)/i;

function isNoise(text) {
  return NOISE_PATTERNS.some((p) => p.test(text));
}

function extractRelevantBlocks() {
  const blocks = [];
  const walker = document.createTreeWalker(
    document.body,
    NodeFilter.SHOW_TEXT,
    {
      acceptNode: (node) => {
        const parent = node.parentElement;
        if (!parent) return NodeFilter.FILTER_REJECT;
        const tag = parent.tagName;
        if (['SCRIPT', 'STYLE', 'NOSCRIPT'].includes(tag)) return NodeFilter.FILTER_REJECT;

        const text = (node.textContent || '').replace(/\s+/g, ' ').trim();
        if (text.length < 25) return NodeFilter.FILTER_REJECT;
        if (isNoise(text)) return NodeFilter.FILTER_REJECT;
        return NodeFilter.FILTER_ACCEPT;
      },
    }
  );

  let node;
  while ((node = walker.nextNode())) {
    const text = (node.textContent || '').replace(/\s+/g, ' ').trim();
    blocks.push({ text });
  }

  const suspicious = blocks.filter((b) => SUSPICIOUS_HINTS.test(b.text));
  const informative = blocks.filter((b) => !SUSPICIOUS_HINTS.test(b.text)).slice(0, 20);
  return [...suspicious, ...informative].slice(0, 50);
}

async function analyzeText(text) {
  const response = await fetch(API_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ text }),
    signal: AbortSignal.timeout(10000),
  });

  if (!response.ok) throw new Error(`API returned ${response.status}`);
  return response.json();
}

function clearHighlights() {
  const highlights = document.querySelectorAll('.surakshaai-highlight, .surakshaai-link-highlight');
  highlights.forEach((el) => {
    el.classList.remove('surakshaai-highlight');
    el.classList.remove('surakshaai-link-highlight');
    el.removeAttribute('data-surakshaai-risk');
  });
}

function highlightSuspiciousText(segments, harmfulLinks = []) {
  clearHighlights();

  if (!segments || segments.length === 0) return;

  const walker = document.createTreeWalker(
    document.body,
    NodeFilter.SHOW_TEXT,
    {
      acceptNode: (node) => {
        const parent = node.parentElement;
        if (!parent) return NodeFilter.FILTER_REJECT;
        const tag = parent.tagName;
        if (['SCRIPT', 'STYLE', 'NOSCRIPT'].includes(tag)) return NodeFilter.FILTER_REJECT;
        return NodeFilter.FILTER_ACCEPT;
      },
    }
  );

  let node;
  while ((node = walker.nextNode())) {
    const nodeText = node.textContent || '';

    for (const segment of segments) {
      const phrase = segment.phrase || '';
      if (!phrase || phrase.length < 20) continue;

      // Check if this text node contains the suspicious phrase
      const cleanNodeText = nodeText.replace(/\s+/g, ' ').trim();
      const cleanPhrase = phrase.replace(/\s+/g, ' ').trim().slice(0, 200);

      if (cleanNodeText.includes(cleanPhrase) || cleanPhrase.includes(cleanNodeText)) {
        const parent = node.parentElement;
        if (parent && !parent.classList.contains('surakshaai-highlight')) {
          parent.classList.add('surakshaai-highlight');
          parent.title = `⚠️ Risk: ${(segment.risk_score * 100).toFixed(0)}% - ${segment.reason || 'Suspicious pattern detected'}`;

          // If highlighted message has hyperlinks, highlight those links as well.
          const linkedElements = [parent, ...parent.querySelectorAll('a')];
          linkedElements.forEach((el) => {
            if (el.tagName === 'A' || el.closest('a')) {
              const anchor = el.tagName === 'A' ? el : el.closest('a');
              if (anchor) {
                anchor.classList.add('surakshaai-link-highlight');
                anchor.setAttribute('data-surakshaai-risk', `${(segment.risk_score * 100).toFixed(0)}%`);
              }
            }
          });
        }
      }
    }
  }

  // Explicit harmful link highlighting from backend output.
  if (harmfulLinks.length) {
    const anchors = document.querySelectorAll('a[href]');
    anchors.forEach((anchor) => {
      const href = anchor.getAttribute('href') || '';
      const absoluteHref = anchor.href || '';
      const isHarmful = harmfulLinks.some((link) => href.includes(link) || absoluteHref.includes(link));
      if (isHarmful) {
        anchor.classList.add('surakshaai-link-highlight');
        anchor.setAttribute('data-surakshaai-risk', 'Harmful link');
      }
    });
  }
}

async function scanPage() {
  if (!isProtectionActive) return;

  const blocks = extractRelevantBlocks();
  if (!blocks.length) {
    clearHighlights();
    chrome.runtime.sendMessage({
      action: 'SCAN_RESULT',
      data: {
        risk_score: 0,
        risk_level: 'SAFE',
        context_boost: 0,
        detected_signals: [],
        suspicious_segments: [],
        structured_explanation: {
          risk_level: 'SAFE',
          primary_reason: 'No relevant text blocks found to scan.',
          psychological_tactics: [],
          technical_indicators: [],
          confidence: 'Low',
        },
      },
    });
    return;
  }

  let text = blocks.map((b) => b.text).join('\n\n');
  if (text.length > 4200) text = text.slice(0, 4200);

  try {
    const result = await analyzeText(text);

    // Highlight suspicious segments on the page
    if (result.suspicious_segments && result.suspicious_segments.length > 0) {
      highlightSuspiciousText(result.suspicious_segments, result.harmful_links || []);
    } else {
      clearHighlights();
    }

    chrome.runtime.sendMessage({
      action: 'SCAN_RESULT',
      data: {
        ...result,
        scanned_blocks: blocks.length,
      },
    });
  } catch (error) {
    clearHighlights();
    chrome.runtime.sendMessage({
      action: 'SCAN_RESULT',
      data: {
        risk_score: 0,
        risk_level: 'SAFE',
        context_boost: 0,
        detected_signals: [],
        suspicious_segments: [],
        structured_explanation: {
          risk_level: 'SAFE',
          primary_reason: `Scan failed: ${error.message}`,
          psychological_tactics: [],
          technical_indicators: [],
          confidence: 'Low',
        },
      },
    });
  }
}

chrome.runtime.onMessage.addListener((message) => {
  if (message.action === 'START_SCAN') {
    isProtectionActive = true;
    scanPage();
  }
  if (message.action === 'STOP_SCAN') {
    isProtectionActive = false;
    clearHighlights();
  }
});
