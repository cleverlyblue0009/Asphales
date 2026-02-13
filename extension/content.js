const API_URL = 'http://localhost:8000/analyze';
const highlights = [];
let isProtectionActive = false;

console.log('🛡️ SurakshaAI Shield loaded on this page');

// ============ EXTRACT TEXT FROM PAGE ============
function extractTextBlocks() {
  console.log('📝 Extracting text from page...');
  const blocks = [];
  
  // Walk through all text nodes in the page
  const walker = document.createTreeWalker(
    document.body,
    NodeFilter.SHOW_TEXT,
    {
      acceptNode: (node) => {
        const parent = node.parentElement;
        if (!parent) return NodeFilter.FILTER_REJECT;
        
        // Skip script, style tags
        const tag = parent.tagName;
        if (['SCRIPT', 'STYLE', 'NOSCRIPT'].includes(tag)) {
          return NodeFilter.FILTER_REJECT;
        }
        
        // Skip very short text
        const text = node.textContent.trim();
        if (text.length < 20) return NodeFilter.FILTER_REJECT;
        
        return NodeFilter.FILTER_ACCEPT;
      }
    }
  );
  
  let node;
  while (node = walker.nextNode()) {
    blocks.push({
      node: node,
      text: node.textContent.trim()
    });
  }
  
  console.log(`✅ Found ${blocks.length} text blocks`);

  blocks.forEach((block, index) => {
    console.log(`📦 Block ${index + 1}:`, block.text);
  });

  return blocks;
}

// ============ CALL BACKEND API ============
async function analyzeText(text) {
  console.log('🔍 Sending text to AI for analysis...');
  
  try {
    const response = await fetch(API_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ text: text }),
      signal: AbortSignal.timeout(8000) // 8 second timeout
    });
    
    if (!response.ok) {
      throw new Error(`API returned ${response.status}`);
    }
    
    const result = await response.json();
    console.log('✅ Analysis complete:', result);
    return result;
    
  } catch (error) {
    console.error('❌ API call failed:', error);
    
    // FALLBACK: Use simple pattern matching
    return useFallbackDetection(text);
  }
}

// ============ FALLBACK DETECTION ============
function useFallbackDetection(text) {
  console.log('⚠️ Using fallback detection');

  const dangerousPatterns = {
    // Hinglish patterns
    'password share karo': { risk: 90, explanation: 'असली banks कभी भी password नहीं मांगते। यह scam है।' },
    'otp batao': { risk: 95, explanation: 'OTP केवल आप के लिए है। किसी को भी share मत करो।' },
    'otp bhejo': { risk: 95, explanation: 'OTP केवल आप के लिए है। किसी को भी share मत करो।' },
    'turant verify': { risk: 75, explanation: 'Urgency एक common phishing tactic है।' },
    'account block hoga': { risk: 80, explanation: 'डराने की कोशिश है। Bank ऐसे message नहीं भेजते।' },
    'cvv enter': { risk: 95, explanation: 'CVV कभी किसी को मत दो। यह fraud है।' },
    'bank details bhejo': { risk: 90, explanation: 'Bank details message में मत भेजो। Scam है।' },
    'lottery jeet': { risk: 85, explanation: 'Fake lottery scam है। कुछ भी share मत करो।' },
    'police department': { risk: 70, explanation: 'Police message से payment नहीं मांगती। Fake है।' },
    'kyc update karo': { risk: 75, explanation: 'Bank कभी WhatsApp पर KYC update नहीं मांगता।' },
    // English patterns
    'enter your otp': { risk: 92, explanation: 'No legitimate service asks for OTP via message. This is a scam.' },
    'share your otp': { risk: 92, explanation: 'Never share your OTP with anyone. This is a scam.' },
    'enter your password': { risk: 90, explanation: 'Legitimate services never ask for passwords via messages.' },
    'debit card details': { risk: 88, explanation: 'Never share card details on messaging apps. This is a scam.' },
    'credit card details': { risk: 88, explanation: 'Never share card details on messaging apps. This is a scam.' },
    'account will be blocked': { risk: 82, explanation: 'Scare tactic. Banks do not send such messages on WhatsApp.' },
    'account will be suspended': { risk: 82, explanation: 'Scare tactic. Banks do not threaten via WhatsApp.' },
    'permanent suspension': { risk: 80, explanation: 'Fear tactic used by scammers. Real banks contact you officially.' },
    'suspicious activity': { risk: 75, explanation: 'Banks do not report suspicious activity via WhatsApp messages.' },
    'verify your kyc': { risk: 80, explanation: 'KYC verification is never done through WhatsApp. This is a scam.' },
    'verify immediately': { risk: 78, explanation: 'Urgency is a classic phishing tactic. Do not act hastily.' },
    'within 24 hours': { risk: 72, explanation: 'Artificial deadline to pressure you. Real banks give proper notice.' },
    'click here and enter': { risk: 80, explanation: 'Never click suspicious links asking for personal information.' },
    'click here to verify': { risk: 78, explanation: 'Phishing link detected. Do not click unknown verification links.' },
    'you have won': { risk: 82, explanation: 'Lottery/prize scam. You cannot win contests you did not enter.' },
    'claim your prize': { risk: 82, explanation: 'Prize claim scam. Legitimate prizes do not require messaging.' },
    'dear customer': { risk: 55, explanation: 'Generic greeting often used in phishing messages.' },
    'sbi account': { risk: 65, explanation: 'SBI does not contact customers via WhatsApp for account issues.' },
    'unauthorized transaction': { risk: 78, explanation: 'Scare tactic. Contact your bank directly to verify.' }
  };

  const threats = [];
  const lowerText = text.toLowerCase();

  for (const [phrase, info] of Object.entries(dangerousPatterns)) {
    if (lowerText.includes(phrase)) {
      threats.push({
        phrase: phrase,
        risk: info.risk,
        explanation: info.explanation
      });
    }
  }

  return {
    overall_risk: threats.length > 0 ? Math.max(...threats.map(t => t.risk)) : 0,
    threats: threats
  };
}

// ============ HIGHLIGHT DANGEROUS TEXT ============
function highlightText(textNode, phrase, risk, explanation) {
  const text = textNode.textContent;
  const lowerText = text.toLowerCase();
  const lowerPhrase = phrase.toLowerCase();
  const index = lowerText.indexOf(lowerPhrase);
  
  if (index === -1) return;
  
  console.log(`🎯 Highlighting: "${phrase}" with risk ${risk}%`);
  
  try {
    const range = document.createRange();
    range.setStart(textNode, index);
    range.setEnd(textNode, index + phrase.length);
    
    const span = document.createElement('span');
    span.className = 'surakshaai-highlight';
    span.dataset.risk = risk;
    span.dataset.explanation = explanation;
    span.dataset.phrase = phrase;
    
    // Add click handler
    span.addEventListener('click', (e) => {
      e.stopPropagation();
      showTooltip(e.clientX, e.clientY, risk, explanation);
    });
    
    range.surroundContents(span);
    highlights.push(span);
    
  } catch (e) {
    console.warn('Could not highlight phrase:', phrase, e);
  }
}

// ============ SHOW TOOLTIP ============
function showTooltip(x, y, risk, explanation) {
  // Remove any existing tooltip
  document.querySelectorAll('.surakshaai-tooltip').forEach(t => t.remove());
  
  const tooltip = document.createElement('div');
  tooltip.className = 'surakshaai-tooltip';
  
  const riskLevel = risk > 70 ? 'high' : risk > 40 ? 'medium' : 'low';
  const riskText = risk > 70 ? 'High Risk' : risk > 40 ? 'Medium Risk' : 'Low Risk';
  
  tooltip.innerHTML = `
    <div class="risk-badge risk-${riskLevel}">${riskText}: ${risk}%</div>
    <div>${explanation}</div>
  `;
  
  document.body.appendChild(tooltip);
  
  // Position tooltip
  tooltip.style.left = `${Math.min(x, window.innerWidth - 370)}px`;
  tooltip.style.top = `${y + 10}px`;
  
  // Auto-remove after 6 seconds
  setTimeout(() => tooltip.remove(), 6000);
  
  // Remove on click anywhere
  document.addEventListener('click', () => tooltip.remove(), { once: true });
}

// ============ MAIN SCAN FUNCTION ============
async function scanPage() {
  if (!isProtectionActive) return;

  console.log('🔍 Starting page scan...');

  // Clear previous highlights before scanning again
  clearHighlights();

  // Extract text blocks
  const blocks = extractTextBlocks();

  if (!blocks || blocks.length === 0) {
    console.log('No text found on page');
    return;
  }

  console.log(`📦 Total blocks found: ${blocks.length}`);

  // 🔒 Limit number of blocks (avoid massive pages)
  const MAX_BLOCKS = 50;
  const limitedBlocks = blocks.slice(0, MAX_BLOCKS);

  console.log(`✂️ Using first ${limitedBlocks.length} blocks`);

  let totalThreats = 0;

  // Analyze each block individually for better accuracy
  for (const block of limitedBlocks) {
    const text = block.text;

    // Skip very short blocks that are unlikely to be messages
    if (text.length < 30) continue;

    try {
      const result = await analyzeText(text);

      if (!result) continue;

      if (result.threats && result.threats.length > 0) {
        console.log(`⚠️ Found ${result.threats.length} threat(s) in block: "${text.substring(0, 60)}..."`);
        totalThreats += result.threats.length;

        result.threats.forEach(threat => {
          if (block.text.toLowerCase().includes(threat.phrase.toLowerCase())) {
            highlightText(
              block.node,
              threat.phrase,
              threat.risk,
              threat.explanation || "Suspicious content detected."
            );
          }
        });
      }
    } catch (err) {
      console.warn("⚠️ Error analyzing block:", err);
    }
  }

  if (totalThreats === 0) {
    console.log('✅ No threats detected in any block');
    chrome.runtime.sendMessage({
      action: "SCAN_RESULT",
      data: { overall_risk: 0, threats: [] }
    });
  } else {
    console.log(`🚨 Total threats found across all blocks: ${totalThreats}`);
  }
}

// ============ CLEAR HIGHLIGHTS ============
function clearHighlights() {
  console.log('🧹 Clearing all highlights...');
  highlights.forEach(span => {
    const parent = span.parentNode;
    if (parent) {
      parent.replaceChild(document.createTextNode(span.textContent), span);
    }
  });
  highlights.length = 0;
  
  // Remove tooltips
  document.querySelectorAll('.surakshaai-tooltip').forEach(t => t.remove());
}

// ============ MESSAGE HANDLER ============
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  console.log('📨 Received message:', message);
  
  if (message.action === 'START_SCAN') {
    isProtectionActive = true;
    console.log('✅ Protection activated');
    scanPage();
  } else if (message.action === 'STOP_SCAN') {
    isProtectionActive = false;
    console.log('⏹️ Protection deactivated');
    clearHighlights();
  }
});

// ============ INITIALIZATION ============
console.log('🚀 SurakshaAI Shield ready!');
