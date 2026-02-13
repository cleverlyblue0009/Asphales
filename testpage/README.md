# Phishing Simulation Testing Suite

This folder contains standalone HTML pages designed for testing a Chrome phishing detection extension.

## 📁 Files Included

1. **whatsapp.html** - WhatsApp-style messaging interface
2. **imessage.html** - Apple iMessage interface
3. **messenger.html** - Facebook Messenger interface
4. **gmail.html** - Gmail email interface
5. **sms.html** - SMS messaging interface
6. **banking_portal.html** - Online banking dashboard
7. **government_notice.html** - Government notice portal

## 🎯 Purpose

Each page simulates a different messaging/communication platform and contains:
- ✅ 5+ clear phishing cases with urgency and suspicious links
- ✅ 5+ safe/legitimate messages
- ✅ 3+ multilingual code-mixed examples (Hindi, Tamil, Bengali, Malayalam with English)
- ✅ 2+ adversarial spelling variations (ver1fy, acc0unt, urg3nt)
- ✅ Various contextual cases (urgency + link, authority + link, etc.)

## 🚀 How to Run

### One-Line Command (Using Python)

```bash
python3 -m http.server 8000 -d testpage
```

Then open your browser and navigate to:
- http://localhost:8000/whatsapp.html
- http://localhost:8000/imessage.html
- http://localhost:8000/messenger.html
- http://localhost:8000/gmail.html
- http://localhost:8000/sms.html
- http://localhost:8000/banking_portal.html
- http://localhost:8000/government_notice.html

### Alternative Methods

**Using Node.js (http-server):**
```bash
npx http-server testpage -p 8000
```

**Using PHP:**
```bash
php -S localhost:8000 -t testpage
```

**Direct File Access:**
Simply open any HTML file directly in your browser:
```bash
# On Linux/Mac
open testpage/whatsapp.html

# On Windows
start testpage/whatsapp.html
```

## 🧪 Testing Your Extension

1. Start a local server using any method above
2. Load your Chrome extension
3. Navigate to each test page
4. The extension should read `document.body.innerText` from each page
5. Verify that your extension correctly identifies:
   - Phishing messages (with urgency, suspicious links, etc.)
   - Safe messages (legitimate notifications)
   - Multilingual phishing attempts
   - Adversarially spelled phishing content

## 📋 Page-Specific Features

### WhatsApp.html
- Green/white bubble design
- Chat-style interface with avatars
- Timestamps
- 20+ message exchanges

### iMessage.html
- Blue/grey Apple-style bubbles
- Minimal white background
- iOS-like typography
- 18+ message exchanges

### Messenger.html
- Facebook blue/grey styling
- Circular avatars
- Message grouping
- 19+ message exchanges

### Gmail.html
- Email inbox layout
- Sender avatars and metadata
- Subject lines and email bodies
- 10+ complete emails

### SMS.html
- Dark mobile interface
- Simple bubble design
- SMS-style formatting
- 19+ text messages

### Banking_Portal.html
- Professional banking dashboard
- Account summary cards
- Notification panel with 16+ notifications
- Sidebar navigation

### Government_Notice.html
- Official government styling
- Indian flag header with emblem
- Formal notice format
- 12+ official notices

## ⚠️ Warning Banner

All pages include a prominent warning banner:
```
⚠ This is a controlled phishing simulation environment.
```

## 🔍 DOM Structure

All message text is:
- Plain HTML text (no canvas, no images for text)
- Accessible via `document.body.innerText`
- Contained in structured div elements with proper classes
- Not hidden in attributes

## 📊 Test Coverage

Each page contains approximately:
- 15-20 total message blocks
- 5-8 phishing cases
- 5-7 safe cases
- 3-4 multilingual examples
- 2-3 adversarial spelling cases

## 🛠️ No Dependencies

- ✅ No React, Vue, or frameworks
- ✅ No external CSS files
- ✅ No external JavaScript
- ✅ No build tools required
- ✅ No npm packages
- ✅ Pure HTML + embedded CSS

## 💡 Tips

1. Use Chrome DevTools to inspect the DOM structure
2. Test `document.body.innerText` in the console to see what your extension will read
3. Check that multilingual content is properly detected
4. Verify adversarial spelling variations are caught
5. Test each platform separately for comprehensive coverage

## 📝 Notes

- All links are dummy links (href="#") for safety
- No actual phishing occurs - this is simulation only
- All pages are fully standalone and work offline
- Pages are responsive and work on different screen sizes

---

**Created for:** Chrome Phishing Detection Extension Testing
**Last Updated:** February 2026
