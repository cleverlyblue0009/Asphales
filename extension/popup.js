// Track if protection is active
let isActive = false;

const toggleBtn = document.getElementById('toggleBtn');
const statusDiv = document.getElementById('status');
const infoDiv = document.getElementById('info');
const resultDiv = document.getElementById('result');

// Listen for messages from content script (scan results)
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  console.log('Popup received message:', message);

  if (message.action === 'SCAN_STARTED') {
    infoDiv.style.display = 'block';
    infoDiv.textContent = 'Scanning webpage for phishing threats...';
    infoDiv.className = 'info scanning';
    resultDiv.style.display = 'none';
  }

  if (message.action === 'SCAN_COMPLETE') {
    infoDiv.style.display = 'none';

    resultDiv.style.display = 'block';

    if (message.error) {
      resultDiv.className = 'result error';
      resultDiv.innerHTML = `<div class="result-icon">&#9888;</div><div>${message.error}</div>`;
    } else if (message.threats > 0) {
      const severityClass = message.severity === 'critical' || message.severity === 'high' ? 'danger' : message.severity === 'medium' ? 'warning' : 'safe';
      resultDiv.className = `result ${severityClass}`;
      resultDiv.innerHTML = `
        <div class="result-icon">${severityClass === 'danger' ? '&#9888;' : '&#9888;'}</div>
        <div class="result-text">
          <strong>${message.threats} threat${message.threats > 1 ? 's' : ''} detected</strong>
          <div class="result-detail">Risk: ${message.overall_risk}% (${message.severity})</div>
          <div class="result-detail">Click highlighted text on page for details</div>
        </div>
      `;
    } else {
      resultDiv.className = 'result safe';
      resultDiv.innerHTML = `
        <div class="result-icon">&#10003;</div>
        <div class="result-text">
          <strong>Page looks safe</strong>
          <div class="result-detail">No phishing threats detected</div>
        </div>
      `;
    }
  }
});

// When button is clicked
toggleBtn.addEventListener('click', async () => {
  isActive = !isActive;

  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

  try {
    chrome.tabs.sendMessage(tab.id, {
      action: isActive ? 'START_SCAN' : 'STOP_SCAN'
    });
  } catch (e) {
    console.error('Failed to send message to content script:', e);
    resultDiv.style.display = 'block';
    resultDiv.className = 'result error';
    resultDiv.innerHTML = '<div>Could not connect to page. Try refreshing.</div>';
    isActive = false;
    return;
  }

  // Save state
  chrome.storage.local.set({ isActive: isActive });

  if (isActive) {
    statusDiv.textContent = 'Protection: ON';
    statusDiv.className = 'status active';
    toggleBtn.textContent = 'Deactivate Protection';
    infoDiv.style.display = 'block';
    infoDiv.textContent = 'Scanning webpage for phishing threats...';
    infoDiv.className = 'info scanning';
    resultDiv.style.display = 'none';
  } else {
    statusDiv.textContent = 'Protection: OFF';
    statusDiv.className = 'status inactive';
    toggleBtn.textContent = 'Activate Protection';
    infoDiv.style.display = 'none';
    resultDiv.style.display = 'none';
  }
});

// Load saved state when popup opens
chrome.storage.local.get(['isActive'], (result) => {
  if (result.isActive) {
    isActive = true;
    statusDiv.textContent = 'Protection: ON';
    statusDiv.className = 'status active';
    toggleBtn.textContent = 'Deactivate Protection';

    // Check current status from content script
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs[0]) {
        chrome.tabs.sendMessage(tabs[0].id, { action: 'GET_STATUS' }, (response) => {
          if (chrome.runtime.lastError) return;
          if (response && response.threats > 0) {
            resultDiv.style.display = 'block';
            resultDiv.className = 'result danger';
            resultDiv.innerHTML = `
              <div class="result-icon">&#9888;</div>
              <div class="result-text">
                <strong>${response.threats} threat${response.threats > 1 ? 's' : ''} highlighted</strong>
                <div class="result-detail">Click highlighted text on page for details</div>
              </div>
            `;
          }
        });
      }
    });
  }
});
