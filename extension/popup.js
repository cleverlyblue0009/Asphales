let isActive = false;

const toggleBtn = document.getElementById('toggleBtn');
const statusDiv = document.getElementById('status');
const infoDiv = document.getElementById('info');
const scanSummaryDiv = document.getElementById('scanSummary');
const threatListDiv = document.getElementById('threatList');

function levelColor(level) {
  if (level === 'HIGH RISK') return '#b71c1c';
  if (level === 'MEDIUM RISK') return '#ef6c00';
  return '#2e7d32';
}

function renderResult(result) {
  const riskScore = Number(result?.risk_score || 0);
  const level = result?.risk_level || 'LOW RISK';
  const contextBoost = Number(result?.context_boost || 0);
  const signals = result?.detected_signals || [];
  const explanation = result?.structured_explanation || {};
  const segments = result?.suspicious_segments || [];
  const harmfulLinks = result?.harmful_links || [];
  const scannedBlocks = result?.scanned_blocks ?? 'N/A';

  scanSummaryDiv.style.display = 'block';
  scanSummaryDiv.innerHTML = `
    <div style="display:flex;justify-content:space-between;align-items:center;">
      <strong>Suspicion Level</strong>
      <span style="padding:4px 8px;border-radius:999px;color:#fff;background:${levelColor(level)}">${level}</span>
    </div>
    <div style="margin-top:8px;">Threat Score: <strong>${(riskScore * 100).toFixed(1)}%</strong></div>
    <div>Context Impact: <strong>${contextBoost >= 0 ? '+' : ''}${(contextBoost * 100).toFixed(1)}%</strong></div>
    <div>Scanned Blocks: <strong>${scannedBlocks}</strong></div>
  `;

  const tactics = explanation.psychological_tactics || [];
  const indicators = explanation.technical_indicators || [];

  const segmentHtml = segments.length
    ? `<div class="threat-item"><div class="threat-head">Context-Aware Suspicious Snippets</div>
      ${segments.slice(0, 5).map((s) => `<div class="threat-phrase">• ${(s.phrase || '').slice(0, 140)}</div><div class="threat-explain">Risk ${(Number(s.risk_score || 0) * 100).toFixed(0)}% • ${s.reason || 'Potential phishing context'}</div>`).join('')}
    </div>`
    : `<div class="threat-item safe"><div class="threat-head">Context-Aware Suspicious Snippets</div><div class="threat-phrase">No suspicious snippets were detected.</div></div>`;

  const harmfulLinksHtml = harmfulLinks.length
    ? `<div class="threat-item"><div class="threat-head">Harmful Links</div>${harmfulLinks.map((link) => `<div class="threat-phrase">• ${link}</div>`).join('')}</div>`
    : `<div class="threat-item safe"><div class="threat-head">Harmful Links</div><div class="threat-phrase">No harmful links detected.</div></div>`;

  threatListDiv.innerHTML = `
    <div class="threat-item">
      <div class="threat-head">Manipulation Radar</div>
      <div class="threat-phrase">${tactics.length ? tactics.join(', ') : 'No clear manipulation tactic detected.'}</div>
      <div class="threat-explain"><strong>Primary Reason:</strong> ${explanation.primary_reason || 'N/A'}</div>
    </div>
    <div class="threat-item">
      <div class="threat-head">Technical Indicators</div>
      <div class="threat-phrase">${indicators.length ? indicators.join(', ') : 'No technical indicator detected.'}</div>
      <div class="threat-explain"><strong>Signals:</strong> ${signals.length ? signals.join(', ') : 'None'}</div>
    </div>
    ${harmfulLinksHtml}
    ${segmentHtml}
    <div class="threat-item safe">
      <div class="threat-head">Confidence</div>
      <div class="threat-phrase">${explanation.confidence || 'Medium'}</div>
      <div class="threat-explain">Scored using full-context ML windows and deterministic signal analysis.</div>
    </div>
  `;
}

toggleBtn.addEventListener('click', async () => {
  isActive = !isActive;
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

  chrome.tabs.sendMessage(tab.id, {
    action: isActive ? 'START_SCAN' : 'STOP_SCAN',
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
