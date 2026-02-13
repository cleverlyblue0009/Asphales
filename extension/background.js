const ANALYZE_ENDPOINTS = [
  'http://localhost:8000/analyze',
  'http://127.0.0.1:8000/analyze'
];
const DEFAULT_TIMEOUT_MS = 5000;

async function fetchAnalyze(url, text, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text }),
      signal: controller.signal
    });

    if (!response.ok) {
      return { ok: false, status: response.status, error: `API returned ${response.status}` };
    }

    const data = await response.json();
    return { ok: true, data };
  } catch (error) {
    if (error.name === 'AbortError') {
      return { ok: false, error: 'Request timeout after 5 seconds' };
    }
    return { ok: false, error: error.message || 'Network error' };
  } finally {
    clearTimeout(timer);
  }
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'SAVE_STATE') {
    chrome.storage.local.set({ isActive: message.isActive });
    sendResponse({ ok: true });
    return false;
  }

  if (message.action === 'LOG') {
    console.log('SurakshaAI:', message.data);
    sendResponse({ ok: true });
    return false;
  }

  if (message.action === 'ANALYZE_TEXT') {
    const timeoutMs = Number(message.timeoutMs) || DEFAULT_TIMEOUT_MS;
    const text = typeof message.text === 'string' ? message.text : '';

    (async () => {
      let lastFailure = 'Backend not available';

      for (const endpoint of ANALYZE_ENDPOINTS) {
        const result = await fetchAnalyze(endpoint, text, timeoutMs);
        if (result.ok) {
          sendResponse({ ok: true, data: result.data, endpoint });
          return;
        }

        if (result.status === 422) {
          sendResponse({ ok: false, error: 'Page content too large for one request' });
          return;
        }

        lastFailure = result.error || lastFailure;
      }

      sendResponse({ ok: false, error: lastFailure });
    })();

    return true;
  }

  return false;
});

chrome.runtime.onInstalled.addListener(() => {
  console.log('SurakshaAI Shield installed successfully!');
});
