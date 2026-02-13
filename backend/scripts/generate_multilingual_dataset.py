"""Generate a 7,500-row multilingual phishing dataset (synthetic)."""

from __future__ import annotations

import csv
import random
from pathlib import Path

OUT = Path(__file__).resolve().parents[1] / "data" / "phishing_multilingual_7500.csv"

PHISH_BASE = [
    "Your SBI account will be blocked in 24 hours. Verify KYC now and share OTP.",
    "URGENT: RBI alert! card suspend hone wala hai, click link and enter PIN.",
    "Aadhaar PAN re-verify karo warna account freeze ho jayega.",
    "আপনার ব্যাংক অ্যাকাউন্ট ব্লক হবে, এখনই OTP দিন।",
    "உங்கள் வங்கி கணக்கு முடக்கப்படும், OTP உடனே பகிரவும்",
    "మీ ఖాతా బ్లాక్ అవుతుంది, వెంటనే KYC చెయ్యండి మరియు OTP ఇవ్వండి",
    "ತಕ್ಷಣ ನಿಮ್ಮ OTP ಕಳುಹಿಸಿ ಇಲ್ಲವಾದರೆ ಖಾತೆ ಬಂದ್ ಆಗುತ್ತದೆ",
    "আপনার KYC আপডেট করুন, না হলে debit card বন্ধ হয়ে যাবে",
    "पुलिस नोटिस: अभी जुर्माना भरें वरना कानूनी कार्रवाई होगी",
    "Get lottery prize ₹5 lakh now, pay registration fee first",
]

SAFE_BASE = [
    "Class moved to 3 PM tomorrow, please attend on time.",
    "Dinner plan tonight? Let's meet near hostel gate.",
    "আজকের মিটিং ৬ টায় হবে, দয়া করে সময়ে আসবেন",
    "நாளை லேப் கிளாஸ் காலை 9 மணிக்கு உள்ளது",
    "రేపు ప్రాజెక్ట్ రివ్యూ 11 గంటలకు ఉంది",
    "कल assignment submit करना है, भूलना मत",
    "Bank statement downloaded successfully from official app.",
    "Your order has been delivered, thank you for shopping.",
    "Happy birthday! have a great day ahead",
    "Meeting notes attached in the shared drive.",
]

LANG_TAGS = [
    "english", "hinglish", "bengali+english", "tamil+english", "telugu+english",
    "kannada+english", "hindi", "marathi+english", "urdu+english", "mixed-indic"
]

SCAM_TYPES = ["otp", "kyc", "impersonation", "urgency", "money", "link", "credential"]
SAFE_TYPES = ["personal", "education", "work", "social", "commerce"]


def mutate(text: str) -> str:
    prefixes = ["", "Dear customer, ", "Attention! ", "FYI: ", "plz "]
    suffixes = ["", " immediately", " asap", " ✅", " 🙏", " #update"]
    return f"{random.choice(prefixes)}{text}{random.choice(suffixes)}"


def main() -> None:
    random.seed(42)
    OUT.parent.mkdir(parents=True, exist_ok=True)

    rows = []
    for _ in range(3750):
        t = mutate(random.choice(PHISH_BASE))
        rows.append({
            "text": t,
            "label": 1,
            "language_mix": random.choice(LANG_TAGS),
            "category": random.choice(SCAM_TYPES),
            "source": "synthetic_v1",
        })
    for _ in range(3750):
        t = mutate(random.choice(SAFE_BASE))
        rows.append({
            "text": t,
            "label": 0,
            "language_mix": random.choice(LANG_TAGS),
            "category": random.choice(SAFE_TYPES),
            "source": "synthetic_v1",
        })

    random.shuffle(rows)

    with OUT.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["text", "label", "language_mix", "category", "source"])
        writer.writeheader()
        writer.writerows(rows)

    print(f"Wrote {len(rows)} rows to {OUT}")


if __name__ == "__main__":
    main()
