let isActive = false;

const toggleBtn = document.getElementById('toggleBtn');
const statusDiv = document.getElementById('status');
const infoDiv = document.getElementById('info');
const scanSummaryDiv = document.getElementById('scanSummary');
const threatListDiv = document.getElementById('threatList');

function levelColor(level) {
  if (level === 'CRITICAL') return '#b71c1c';
  if (level === 'HIGH RISK') return '#e65100';
  if (level === 'SUSPICIOUS') return '#ef6c00';
  return '#2e7d32';
}

function renderResult(result) {
  const riskScore = Number(result?.risk_score || 0);
  const level = result?.risk_level || 'SAFE';
  const contextBoost = Number(result?.context_boost || 0);
  const signals = result?.detected_signals || [];
  const explanation = result?.structured_explanation || {};
  const segments = result?.suspicious_segments || [];
  const scannedBlocks = result?.scanned_blocks ?? 'N/A';

  scanSummaryDiv.style.display = 'block';
  scanSummaryDiv.innerHTML = `
    <div style="display:flex;justify-content:space-between;align-items:center;">
      <strong>Suspicion Level</strong>
      <span style="padding:4px 8px;border-radius:999px;color:#fff;background:${levelColor(level)}">${level}</span>
    </div>
    <div style="margin-top:8px;">Risk Score: <strong>${(riskScore * 100).toFixed(1)}%</strong></div>
    <div>Context Boost: <strong>+${(contextBoost * 100).toFixed(1)}%</strong></div>
    <div>Scanned Blocks: <strong>${scannedBlocks}</strong></div>
  `;

  const tactics = explanation.psychological_tactics || [];
  const indicators = explanation.technical_indicators || [];

  const segmentHtml = segments.length
    ? `<div class="threat-item"><div class="threat-head">Top Suspicious Snippets</div>
      ${segments.slice(0, 4).map((s) => `<div class="threat-phrase">• ${(s.phrase || '').slice(0, 140)}</div><div class="threat-explain">Risk ${(Number(s.risk_score || 0) * 100).toFixed(0)}%</div>`).join('')}
    </div>`
    : `<div class="threat-item safe"><div class="threat-head">Top Suspicious Snippets</div><div class="threat-phrase">No suspicious snippets were detected.</div></div>`;

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
    ${segmentHtml}
    <div class="threat-item safe">
      <div class="threat-head">Confidence</div>
      <div class="threat-phrase">${explanation.confidence || 'Medium'}</div>
      <div class="threat-explain">ML + deterministic context analysis (GenAI disabled).</div>
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
