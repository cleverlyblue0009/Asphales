"""Generate a 7,500-row multilingual phishing dataset (synthetic, richer coverage)."""

from __future__ import annotations

import csv
import random
from pathlib import Path

OUT = Path(__file__).resolve().parents[1] / "data" / "phishing_multilingual_7500.csv"

PHISH_BASE = [
    "Dear Customer, Your SBI account will be blocked within 24 hours due to suspicious activity. Verify your KYC immediately and enter your OTP and debit card details.",
    "URGENT: RBI alert! card suspend hone wala hai, click link and enter PIN.",
    "Aadhaar PAN re-verify karo warna account freeze ho jayega.",
    "আপনার ব্যাংক অ্যাকাউন্ট ব্লক হবে, এখনই OTP দিন।",
    "உங்கள் வங்கி கணக்கு முடக்கப்படும், OTP உடனே பகிரவும்",
    "మీ ఖాతా బ్లాక్ అవుతుంది, వెంటనే KYC చెయ్యండి మరియు OTP ఇవ్వండి",
    "ತಕ್ಷಣ ನಿಮ್ಮ OTP ಕಳುಹಿಸಿ ಇಲ್ಲವಾದರೆ ಖಾತೆ ಬಂದ್ ಆಗುತ್ತದೆ",
    "আপনার KYC আপডেট করুন, না হলে debit card বন্ধ হয়ে যাবে",
    "पुलिस नोटिस: अभी जुर्माना भरें वरना कानूनी कार्रवाई होगी",
    "Get lottery prize ₹5 lakh now, pay registration fee first",
    "UPI KYC expired. Abhi verify nahi kiya to account band ho jayega.",
    "Paytm security team se bol raha hu, account unlock ke liye OTP share karo",
    "Your account has suspicious login. click here and update CVV now",
    "Sarkari subsidy release ke liye processing fee bhejo",
    "CBI cyber complaint registered. settle immediately to avoid arrest",
    "24 ghante mein KYC नहीं किया तो card permanently blocked",
    "a/c verification pending. confirm netbanking password now",
    "bank e-KYC link: fill card number and OTP to continue",
    "Your PhonePe wallet blocked. share mpin to reactivate",
    "Income tax refund release: verify PAN and bank details now",
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
    "Physics CAT prep session at 6 pm in SJT-308",
    "Please share PYQ pdf in class group",
    "Lab viva postponed to next Monday",
    "Cab details: driver number shared for pickup",
    "Document uploaded to Google Drive for project review",
    "Hostel maintenance visit tomorrow morning",
    "Exam timetable announced on portal",
    "Lunch done? meet at canteen",
    "Seminar registration open on official college website",
    "Your parcel out for delivery",
]

LANG_TAGS = [
    "Assamese+English", "Bengali+English", "Bodo+English", "Dogri+English", "Gujarati+English",
    "Hindi+English", "Kannada+English", "Kashmiri+English", "Konkani+English", "Maithili+English",
    "Malayalam+English", "Manipuri+English", "Marathi+English", "Nepali+English", "Odia+English",
    "Punjabi+English", "Sanskrit+English", "Santali+English", "Sindhi+English", "Tamil+English",
    "Telugu+English", "Urdu+English", "Hinglish", "Tanglish", "mixed-indic"
]

SCAM_TYPES = ["otp", "kyc", "impersonation", "urgency", "money", "link", "credential", "upi", "fear"]
SAFE_TYPES = ["personal", "education", "work", "social", "commerce", "family"]


PREFIXES = ["", "Dear customer, ", "Attention! ", "FYI: ", "plz ", "Important: ", "Alert: "]
SUFFIXES = ["", " immediately", " asap", " ✅", " 🙏", " #update", " kindly respond"]


def mutate(text: str) -> str:
    return f"{random.choice(PREFIXES)}{text}{random.choice(SUFFIXES)}"


def main() -> None:
    random.seed(42)
    OUT.parent.mkdir(parents=True, exist_ok=True)

    rows = []
    for _ in range(3750):
        rows.append({
            "text": mutate(random.choice(PHISH_BASE)),
            "label": 1,
            "language_mix": random.choice(LANG_TAGS),
            "category": random.choice(SCAM_TYPES),
            "source": "synthetic_v2",
        })
    for _ in range(3750):
        rows.append({
            "text": mutate(random.choice(SAFE_BASE)),
            "label": 0,
            "language_mix": random.choice(LANG_TAGS),
            "category": random.choice(SAFE_TYPES),
            "source": "synthetic_v2",
        })

    random.shuffle(rows)

    with OUT.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["text", "label", "language_mix", "category", "source"])
        writer.writeheader()
        writer.writerows(rows)

    print(f"Wrote {len(rows)} rows to {OUT}")


if __name__ == "__main__":
    main()
