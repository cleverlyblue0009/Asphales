"""Language detection utility for multilingual text."""

import re
from typing import Dict, List, Tuple


# Unicode ranges for Indian languages
LANGUAGE_PATTERNS = {
    "Hindi": re.compile(r"[\u0900-\u097F]+"),  # Devanagari
    "Bengali": re.compile(r"[\u0980-\u09FF]+"),  # Bengali
    "Gujarati": re.compile(r"[\u0A80-\u0AFF]+"),  # Gujarati
    "Punjabi": re.compile(r"[\u0A00-\u0A7F]+"),  # Gurmukhi
    "Tamil": re.compile(r"[\u0B80-\u0BFF]+"),  # Tamil
    "Telugu": re.compile(r"[\u0C00-\u0C7F]+"),  # Telugu
    "Kannada": re.compile(r"[\u0C80-\u0CFF]+"),  # Kannada
    "Malayalam": re.compile(r"[\u0D00-\u0D7F]+"),  # Malayalam
    "Marathi": re.compile(r"[\u0900-\u097F]+"),  # Devanagari (same as Hindi)
    "Urdu": re.compile(r"[\u0600-\u06FF]+"),  # Arabic script
}

# Threat keywords in multiple languages
THREAT_KEYWORDS = {
    "Hindi": [
        "बैंक खाता", "तुरंत", "सत्यापन", "ओटीपी", "पासवर्ड", "इनाम", "जीता",
        "ब्लॉक", "बंद", "KYC", "अपडेट", "खाते से", "डेबिट", "क्लिक करें"
    ],
    "Bengali": [
        "ব্যাংক অ্যাকাউন্ট", "এখনই", "যাচাই", "ওটিপি", "পাসওয়ার্ড", "পুরস্কার",
        "ব্লক", "KYC", "আপডেট", "ক্লিক করুন"
    ],
    "Gujarati": [
        "બેંક એકાઉન્ટ", "તરત જ", "ચકાસણી", "ઓટીપી", "પાસવર્ડ", "ઇનામ",
        "બ્લોક", "બંધ", "KYC", "અપડેટ", "ક્લિક કરો"
    ],
    "Tamil": [
        "வங்கி கணக்கு", "உடனே", "சரிபார்", "ஓடிபி", "கடவுச்சொல்", "பரிசு",
        "தடுக்க", "மூடு", "KYC", "புதுப்பிப்பு", "கிளிக்"
    ],
    "Telugu": [
        "బ్యాంక్ ఖాతా", "వెంటనే", "ధృవీకరణ", "OTP", "పాస్వర్డ్", "బహుమతి",
        "బ్లాక్", "మూసివేయు", "KYC", "నవీకరణ", "క్లిక్"
    ],
    "Kannada": [
        "ಬ್ಯಾಂಕ್ ಖಾತೆ", "ತಕ್ಷಣ", "ಪರಿಶೀಲನೆ", "ಓಟಿಪಿ", "ಪಾಸ್ವರ್ಡ್", "ಬಹುಮಾನ",
        "ಬ್ಲಾಕ್", "ಮುಚ್ಚಿ", "KYC", "ನವೀಕರಣ", "ಕ್ಲಿಕ್"
    ],
    "Malayalam": [
        "ബാങ്ക് അക്കൗണ്ട്", "ഉടൻ", "സ്ഥിരീകരണം", "ഒടിപി", "പാസ്വേഡ്", "സമ്മാനം",
        "ബ്ലോക്ക്", "അടയ്ക്കുക", "KYC", "അപ്ഡേറ്റ്", "ക്ലിക്ക്"
    ],
    "Marathi": [
        "बँक खाते", "ताबडतोब", "पडताळणी", "ओटीपी", "पासवर्ड", "बक्षीस",
        "ब्लॉक", "बंद", "KYC", "अद्यतनित", "क्लिक करा"
    ],
    "Urdu": [
        "بینک اکاؤنٹ", "فوری", "تصدیق", "OTP", "پاس ورڈ", "انعام",
        "بلاک", "بند", "KYC", "اپڈیٹ", "کلک کریں"
    ],
    "English": [
        "bank account", "urgent", "verify", "otp", "password", "prize", "won",
        "block", "suspend", "kyc", "update", "click here", "debit"
    ]
}

# Safe/benign keywords in multiple languages
SAFE_KEYWORDS = {
    "Hindi": [
        "क्लास", "प्रोजेक्ट", "होमवर्क", "परीक्षा", "नोट्स", "मीटिंग", "असाइनमेंट",
        "कॉलेज", "स्कूल", "दोस्त", "परिवार", "खाना", "मौसम", "शुभकामनाएं"
    ],
    "Bengali": [
        "ক্লাস", "প্রজেক্ট", "হোমওয়ার্ক", "পরীক্ষা", "নোট", "মিটিং", "অ্যাসাইনমেন্ট",
        "কলেজ", "স্কুল", "বন্ধু", "পরিবার", "খাবার", "আবহাওয়া"
    ],
    "English": [
        "class", "project", "homework", "exam", "notes", "meeting", "assignment",
        "college", "university", "school", "friend", "family", "food", "weather",
        "schedule", "semester", "admission", "tournament", "fixture", "score", "style"
    ]
}


def detect_language(text: str) -> List[Tuple[str, int]]:
    """
    Detect languages present in text.
    Returns list of (language, character_count) tuples, sorted by count.
    """
    if not text:
        return []

    lang_counts: Dict[str, int] = {}

    for lang, pattern in LANGUAGE_PATTERNS.items():
        matches = pattern.findall(text)
        if matches:
            count = sum(len(match) for match in matches)
            lang_counts[lang] = count

    # Check for English (basic Latin alphabet)
    english_matches = re.findall(r"[a-zA-Z]+", text)
    if english_matches:
        lang_counts["English"] = sum(len(match) for match in english_matches)

    # Sort by count descending
    sorted_langs = sorted(lang_counts.items(), key=lambda x: x[1], reverse=True)
    return sorted_langs


def get_primary_language(text: str) -> str:
    """Get the primary (most used) language in text."""
    detected = detect_language(text)
    if not detected:
        return "English"
    return detected[0][0]


def is_code_mixed(text: str) -> bool:
    """Check if text contains multiple languages (code-mixing)."""
    detected = detect_language(text)
    return len(detected) > 1


def count_threat_keywords(text: str, language: str = None) -> int:
    """
    Count threat keywords in text.
    If language is specified, only check that language.
    Otherwise, check all languages.
    """
    if not text:
        return 0

    text_lower = text.lower()
    count = 0

    languages_to_check = [language] if language else THREAT_KEYWORDS.keys()

    for lang in languages_to_check:
        if lang not in THREAT_KEYWORDS:
            continue
        for keyword in THREAT_KEYWORDS[lang]:
            if keyword.lower() in text_lower:
                count += 1

    return count


def count_safe_keywords(text: str, language: str = None) -> int:
    """
    Count safe/benign keywords in text.
    If language is specified, only check that language.
    Otherwise, check all languages.
    """
    if not text:
        return 0

    text_lower = text.lower()
    count = 0

    languages_to_check = [language] if language else SAFE_KEYWORDS.keys()

    for lang in languages_to_check:
        if lang not in SAFE_KEYWORDS:
            continue
        for keyword in SAFE_KEYWORDS[lang]:
            if keyword.lower() in text_lower:
                count += 1

    return count


def get_language_info(text: str) -> Dict:
    """
    Get comprehensive language information about text.

    Returns:
        {
            "primary_language": str,
            "detected_languages": [(lang, count), ...],
            "is_code_mixed": bool,
            "threat_keyword_count": int,
            "safe_keyword_count": int,
            "likely_benign": bool
        }
    """
    detected = detect_language(text)
    primary = detected[0][0] if detected else "English"

    threat_count = count_threat_keywords(text)
    safe_count = count_safe_keywords(text)

    # If text has more safe keywords than threat keywords, likely benign
    likely_benign = safe_count > threat_count and safe_count >= 3

    return {
        "primary_language": primary,
        "detected_languages": detected,
        "is_code_mixed": len(detected) > 1,
        "threat_keyword_count": threat_count,
        "safe_keyword_count": safe_count,
        "likely_benign": likely_benign
    }
