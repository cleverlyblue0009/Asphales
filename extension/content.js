const API_URL = 'http://localhost:8000/analyze';
const highlights = [];
let isProtectionActive = false;
const SUSPICIOUS_BLOCK_HINTS = /(otp|password|kyc|cvv|pin|debit card|credit card|account\s*(blocked|block|suspend|freeze)|verify|click here|sbi|rbi|aadhar|aadhaar|pan|upi|पासवर्ड|ओटीपी|केवाईसी|অটিপি|পাসওয়ার্ড|ஒடிபி|கடவுச்சொல்)/i;

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
    'password share karo': { risk: 90, explanation: 'असली banks कभी भी password नहीं मांगते। यह scam है।' },
    'otp batao': { risk: 95, explanation: 'OTP केवल आप के लिए है। किसी को भी share मत करो।' },
    'turant verify': { risk: 75, explanation: 'Urgency एक common phishing tactic है।' },
    'account block': { risk: 80, explanation: 'डराने की कोशिश है। Bank ऐसे message नहीं भेजते।' },
    'cvv enter': { risk: 95, explanation: 'CVV कभी किसी को मत दो। यह fraud है।' },
    'bank details bhejo': { risk: 90, explanation: 'Bank details message में मत भेजो। Scam है।' },
    'lottery jeet': { risk: 85, explanation: 'Fake lottery scam है। कुछ भी share मत करो।' },
    'police department': { risk: 70, explanation: 'Police message से payment नहीं मांगती। Fake है।' }
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

  // Prioritize suspicious-looking blocks, then fill remaining slots
  const MAX_BLOCKS = 60;
  const suspiciousBlocks = blocks.filter(b => SUSPICIOUS_BLOCK_HINTS.test(b.text));
  const remainingBlocks = blocks.filter(b => !SUSPICIOUS_BLOCK_HINTS.test(b.text));
  const limitedBlocks = [...suspiciousBlocks, ...remainingBlocks].slice(0, MAX_BLOCKS);

  console.log(`✂️ Using ${limitedBlocks.length} prioritized blocks (${suspiciousBlocks.length} suspicious candidates)`);

  // Combine selected blocks
  let fullText = limitedBlocks.map(b => b.text).join('\n\n');

  console.log("🧮 Text length before trim:", fullText.length);

  // 🔒 Hard limit to stay below backend 5000 max_length
  const MAX_LENGTH = 4000;
  if (fullText.length > MAX_LENGTH) {
    console.log(`✂️ Trimming text from ${fullText.length} to ${MAX_LENGTH}`);
    fullText = fullText.slice(0, MAX_LENGTH);
  }

  console.log("📤 Final text length sent:", fullText.length);

  try {
    console.log("📤 FULL TEXT SENT TO API:");
    console.log(fullText);

    const result = await analyzeText(fullText);

    if (!result) {
      console.log('No result returned from analysis');
      return;
    }

    // Highlight threats
    if (result.threats && result.threats.length > 0) {
      console.log(`⚠️ Found ${result.threats.length} threats`);

      result.threats.forEach(threat => {
        limitedBlocks.forEach(block => {
          if (block.text.toLowerCase().includes(threat.phrase.toLowerCase())) {
            highlightText(
              block.node,
              threat.phrase,
              threat.risk,
              threat.explanation || "Suspicious content detected."
            );
          }
        });
      });
    } else {
      console.log('✅ No threats detected');
    }

    chrome.runtime.sendMessage({
      action: "SCAN_RESULT",
      data: {
        ...result,
        scanned_blocks: limitedBlocks.length
      }
    });

  } catch (err) {
    console.error("🚨 Scan failed:", err);
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
