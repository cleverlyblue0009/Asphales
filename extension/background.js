// Background coordinator for popup/content communication and persisted scan results.
chrome.runtime.onMessage.addListener((message, sender) => {
  if (message.action === 'SAVE_STATE') {
    chrome.storage.local.set({ isActive: message.isActive });
  }

  if (message.action === 'SCAN_RESULT') {
    chrome.storage.local.set({ lastScanResult: message.data || {} });
    chrome.runtime.sendMessage(message).catch(() => {
      // Popup may not be open; storage keeps latest result.
    });
  }

  if (message.action === 'LOG') {
    console.log('SurakshaAI:', message.data);
  }
});

chrome.runtime.onInstalled.addListener(() => {
  console.log('SurakshaAI Shield installed successfully!');
});
