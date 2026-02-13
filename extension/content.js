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

async function scanPage() {
  if (!isProtectionActive) return;

  const blocks = extractRelevantBlocks();
  if (!blocks.length) {
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
    chrome.runtime.sendMessage({
      action: 'SCAN_RESULT',
      data: {
        ...result,
        scanned_blocks: blocks.length,
      },
    });
  } catch (error) {
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
  }
});
