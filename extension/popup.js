let isActive = false;

const toggleBtn = document.getElementById('toggleBtn');
const statusDiv = document.getElementById('status');
const infoDiv = document.getElementById('info');
const scanSummaryDiv = document.getElementById('scanSummary');
const threatListDiv = document.getElementById('threatList');

function renderResult(result) {
  const risk = result?.overall_risk ?? 0;
  const severity = (result?.severity || 'low').toUpperCase();
  const threats = result?.threats || [];
  const threatDetected = threats.length > 0 || risk >= 45;

  scanSummaryDiv.style.display = 'block';
  scanSummaryDiv.innerHTML = `<strong>Scan result:</strong> ${threatDetected ? 'Threats detected ⚠️' : 'No threats detected ✅'}<br>
    Risk Score: <strong>${risk}</strong> (${severity})`;

  if (!threats.length) {
    if (risk >= 45) {
      threatListDiv.innerHTML = `<div class="threat-item">
        <div class="threat-head">Risk ${risk}% · model_detected</div>
        <div class="threat-phrase">Suspicious content found in page text</div>
        <div class="threat-explain">Model detected phishing risk from context even if exact snippet could not be isolated. Please avoid sharing OTP/CVV/KYC details.</div>
      </div>`;
      return;
    }

    threatListDiv.innerHTML = '<div class="threat-item safe">No suspicious message found in scanned blocks.</div>';
    return;
  }

  const topThreats = threats
    .slice()
    .sort((a, b) => (b.risk || 0) - (a.risk || 0))
    .slice(0, 6);

  threatListDiv.innerHTML = topThreats
    .map((threat) => `
      <div class="threat-item">
        <div class="threat-head">Risk ${threat.risk || 0}% · ${threat.category || 'suspicious'}</div>
        <div class="threat-phrase">${threat.phrase || 'Suspicious message segment'}</div>
        <div class="threat-explain">${threat.explanation || 'Potential phishing pattern detected.'}</div>
      </div>`)
    .join('');
}

toggleBtn.addEventListener('click', async () => {
  isActive = !isActive;
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

  chrome.tabs.sendMessage(tab.id, {
    action: isActive ? 'START_SCAN' : 'STOP_SCAN'
  });

  chrome.runtime.sendMessage({ action: 'SAVE_STATE', isActive });

  if (isActive) {
    statusDiv.textContent = 'Protection: ON ✓';
    statusDiv.className = 'status active';
    toggleBtn.textContent = 'Deactivate Protection';
    infoDiv.style.display = 'block';
  } else {
    statusDiv.textContent = 'Protection: OFF';
    statusDiv.className = 'status inactive';
    toggleBtn.textContent = 'Activate Protection';
    infoDiv.style.display = 'none';
    scanSummaryDiv.style.display = 'none';
    threatListDiv.innerHTML = '';
  }
});

chrome.runtime.onMessage.addListener((message) => {
  if (message.action === 'SCAN_RESULT') {
    renderResult(message.data || {});
  }
});

chrome.storage.local.get(['isActive', 'lastScanResult'], (result) => {
  if (result.isActive) {
    isActive = true;
    statusDiv.textContent = 'Protection: ON ✓';
    statusDiv.className = 'status active';
    toggleBtn.textContent = 'Deactivate Protection';
    infoDiv.style.display = 'block';
  }

  if (result.lastScanResult) {
    renderResult(result.lastScanResult);
  }
});
