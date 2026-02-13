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
  const languageInfo = result?.language_info || {};

  scanSummaryDiv.style.display = 'block';
  scanSummaryDiv.innerHTML = `
    <div style="display:flex;justify-content:space-between;align-items:center;">
      <strong>Jokhim Star / जोखिम स्तर</strong>
      <span style="padding:4px 8px;border-radius:999px;color:#fff;background:${levelColor(level)}">${level}</span>
    </div>
    <div style="margin-top:8px;">Threat Score / खतरा स्कोर: <strong>${(riskScore * 100).toFixed(1)}%</strong></div>
    <div>Context Impact / प्रभाव: <strong>${contextBoost >= 0 ? '+' : ''}${(contextBoost * 100).toFixed(1)}%</strong></div>
    <div>Scanned Blocks / स्कैन ब्लॉक्स: <strong>${scannedBlocks}</strong></div>
    ${languageInfo.primary_language ? `<div>Detected Language / भाषा: <strong>${languageInfo.primary_language}</strong></div>` : ''}
  `;

  const tactics = explanation.psychological_tactics || [];
  const tacticsVernacular = explanation.psychological_tactics_vernacular || [];
  const indicators = explanation.technical_indicators || [];
  const indicatorsVernacular = explanation.technical_indicators_vernacular || [];
  const detectedLang = explanation.detected_language || 'English';

  // Format bilingual display
  const formatBilingual = (en, vernacular) => {
    if (!vernacular || en === vernacular || detectedLang === 'English') {
      return en;
    }
    return `${en} <span style="color:#666;font-size:0.9em;">(${vernacular})</span>`;
  };

  // Format tactics display
  const tacticsDisplay = tactics.length
    ? tacticsVernacular.length
      ? tacticsVernacular.join(', ')
      : tactics.map((t, i) => formatBilingual(t, tacticsVernacular[i])).join(', ')
    : 'कोई स्पष्ट हेरफेर रणनीति नहीं मिली।';

  // Format indicators display
  const indicatorsDisplay = indicators.length
    ? indicatorsVernacular.length
      ? indicatorsVernacular.join(', ')
      : indicators.map((ind, i) => formatBilingual(ind, indicatorsVernacular[i])).join(', ')
    : 'कोई तकनीकी संकेत नहीं मिला।';

  // Primary reason (bilingual)
  const primaryReason = explanation.primary_reason || 'No strong phishing indicator detected.';
  const primaryReasonVernacular = explanation.primary_reason_vernacular || '';
  const primaryReasonDisplay = primaryReasonVernacular || formatBilingual(primaryReason, primaryReasonVernacular);
  const romanizedReason = explanation.risk_reason_romanized || result?.genai_validation?.explanation_romanized || '';

  const segmentHtml = segments.length
    ? `<div class="threat-item"><div class="threat-head">Context-Aware Snippets / संदिग्ध अंश</div>
      ${segments.slice(0, 5).map((s) => `<div class="threat-phrase">• ${(s.phrase || '').slice(0, 140)}</div><div class="threat-explain">Risk ${(Number(s.risk_score || 0) * 100).toFixed(0)}% • ${s.reason || 'Potential phishing context'}</div>`).join('')}
    </div>`
    : `<div class="threat-item safe"><div class="threat-head">Context-Aware Snippets / संदिग्ध अंश</div><div class="threat-phrase">कोई संदिग्ध अंश नहीं मिला।</div></div>`;

  const harmfulLinksHtml = harmfulLinks.length
    ? `<div class="threat-item"><div class="threat-head">Harmful Links / खतरनाक लिंक</div>${harmfulLinks.map((link) => `<div class="threat-phrase" style="word-break:break-all;">• ${link}</div>`).join('')}</div>`
    : `<div class="threat-item safe"><div class="threat-head">Harmful Links / खतरनाक लिंक</div><div class="threat-phrase">कोई हानिकारक लिंक नहीं मिला।</div></div>`;

  threatListDiv.innerHTML = `
    <div class="threat-item">
      <div class="threat-head">Manipulation Radar / सामाजिक हेरफेर</div>
      <div class="threat-phrase">${tacticsDisplay}</div>
      <div class="threat-explain"><strong>मुख्य कारण:</strong> ${primaryReasonDisplay}</div>${romanizedReason ? `<div class="threat-explain"><strong>Romanized:</strong> ${romanizedReason}</div>` : ''}
    </div>
    <div class="threat-item">
      <div class="threat-head">Technical Indicators / तकनीकी संकेत</div>
      <div class="threat-phrase">${indicatorsDisplay}</div>
      <div class="threat-explain"><strong>Detected Signals:</strong> ${signals.length ? signals.join(', ') : 'कोई नहीं'}</div>
    </div>
    ${harmfulLinksHtml}
    ${segmentHtml}
    <div class="threat-item safe">
      <div class="threat-head">Confidence / भरोसा</div>
      <div class="threat-phrase">${explanation.confidence || 'Medium'}</div>
      <div class="threat-explain">Context-aware ML और बहुभाषी pattern detection से score निकाला गया।</div>
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
    statusDiv.textContent = 'Protection: ON ✓ / सुरक्षा चालू';
    statusDiv.className = 'status active';
    toggleBtn.textContent = 'Deactivate / सुरक्षा बंद करें';
    infoDiv.style.display = 'block';
  } else {
    statusDiv.textContent = 'Protection: OFF / सुरक्षा बंद';
    statusDiv.className = 'status inactive';
    toggleBtn.textContent = 'Activate / सुरक्षा चालू करें';
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
    statusDiv.textContent = 'Protection: ON ✓ / सुरक्षा चालू';
    statusDiv.className = 'status active';
    toggleBtn.textContent = 'Deactivate / सुरक्षा बंद करें';
    infoDiv.style.display = 'block';
  }

  if (result.lastScanResult) {
    renderResult(result.lastScanResult);
  }
});
