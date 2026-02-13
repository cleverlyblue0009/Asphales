const API_URL = 'http://localhost:8000/analyze_text';
let isProtectionActive = false;

function extractVisibleText() {
  const text = (document.body?.innerText || '').replace(/\s+/g, ' ').trim();
  return text.slice(0, 4800);
}

async function analyzeText(text) {
  const response = await fetch(API_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ text }),
    signal: AbortSignal.timeout(8000)
  });
  if (!response.ok) {
    throw new Error(`API returned ${response.status}`);
  }
  return response.json();
}

async function scanPage() {
  if (!isProtectionActive) return;
  const text = extractVisibleText();
  if (!text) return;

  try {
    const result = await analyzeText(text);
    chrome.runtime.sendMessage({ action: 'SCAN_RESULT', data: result });
  } catch (error) {
    chrome.runtime.sendMessage({
      action: 'SCAN_RESULT',
      data: {
        risk_score: 0,
        risk_level: 'SAFE',
        context_boost: 0,
        detected_signals: [],
        structured_explanation: {
          primary_reason: `Scan failed: ${error.message}`,
          psychological_tactics: [],
          technical_indicators: [],
          confidence: 'Low'
        }
      }
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
