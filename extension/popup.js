let isActive = false;

const activateBtn = document.getElementById('activateBtn');
const deactivateBtn = document.getElementById('deactivateBtn');
const statusDiv = document.getElementById('status');
const infoDiv = document.getElementById('info');
const threatsDiv = document.getElementById('threatCount');

function setUiState() {
  activateBtn.style.display = isActive ? 'none' : 'block';
  deactivateBtn.style.display = isActive ? 'block' : 'none';

  statusDiv.textContent = isActive ? 'Protection: ON ✓' : 'Protection: OFF';
  statusDiv.className = `status ${isActive ? 'active' : 'inactive'}`;
}

async function getActiveTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab;
}

activateBtn.addEventListener('click', async () => {
  const tab = await getActiveTab();
  if (!tab?.id) return;

  statusDiv.textContent = 'Scanning...';
  statusDiv.className = 'status inactive';
  infoDiv.textContent = 'Analyzing page for phishing signals...';
  threatsDiv.textContent = '';

  try {
    const result = await chrome.tabs.sendMessage(tab.id, { action: 'START_SCAN' });
    isActive = true;
    chrome.storage.local.set({ isActive: true });

    setUiState();
    infoDiv.textContent = result?.message || 'Scan complete.';
    threatsDiv.textContent = `Threats detected: ${result?.threats ?? 0}`;
  } catch (error) {
    console.error('Failed to start scan:', error);
    infoDiv.textContent = 'Could not connect to page script.';
    statusDiv.textContent = 'Protection: OFF';
    statusDiv.className = 'status inactive';
  }
});

deactivateBtn.addEventListener('click', async () => {
  const tab = await getActiveTab();
  if (!tab?.id) return;

  try {
    await chrome.tabs.sendMessage(tab.id, { action: 'STOP_SCAN' });
  } catch (error) {
    console.error('Failed to stop scan:', error);
  }

  isActive = false;
  chrome.storage.local.set({ isActive: false });
  setUiState();
  infoDiv.textContent = 'Highlights cleared.';
  threatsDiv.textContent = 'Threats detected: 0';
});

chrome.storage.local.get(['isActive'], (result) => {
  isActive = Boolean(result.isActive);
  setUiState();
  threatsDiv.textContent = 'Threats detected: 0';
  infoDiv.textContent = isActive
    ? 'Protection active. Click Deactivate to clear highlights.'
    : 'Activate protection to scan this page.';
});
