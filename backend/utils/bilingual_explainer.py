"""Bilingual explanation generator for phishing threats."""

from typing import Dict, List

# Explanation templates in multiple languages
EXPLANATIONS = {
    "Hindi": {
        "primary_reasons": {
            "bank_impersonation": "यह संदेश बैंक का नकली रूप धारण कर रहा है और आपकी निजी जानकारी मांग रहा है।",
            "urgency_tactic": "यह संदेश तुरंत कार्रवाई करने का दबाव बना रहा है जो फिशिंग की रणनीति है।",
            "credential_request": "यह संदेश आपका OTP, पासवर्ड या अन्य गोपनीय जानकारी मांग रहा है।",
            "suspicious_link": "इसमें संदिग्ध लिंक है जो आपको नकली वेबसाइट पर ले जा सकता है।",
            "reward_scam": "यह एक नकली इनाम/पुरस्कार का संदेश है जो आपकी जानकारी चुराने की कोशिश कर रहा है।",
            "account_threat": "यह संदेश डराने के लिए आपके खाते को ब्लॉक करने की धमकी दे रहा है।",
            "safe": "यह संदेश सुरक्षित प्रतीत होता है और कोई स्पष्ट खतरा नहीं दिखता।"
        },
        "tactics": {
            "Urgency": "तात्कालिकता (तुरंत कार्रवाई की मांग)",
            "Authority": "अधिकार का दुरुपयोग (बैंक/सरकार का नकली रूप)",
            "Fear": "डर (खाता बंद होने की धमकी)",
            "Greed": "लालच (मुफ्त इनाम/पैसे)"
        },
        "indicators": {
            "Suspicious URL": "संदिग्ध वेबसाइट लिंक",
            "Credential Harvesting Pattern": "निजी जानकारी मांगने का पैटर्न",
            "Misspelled Domain": "गलत स्पेलिंग वाला डोमेन",
            "IP Address URL": "IP पते वाला लिंक"
        }
    },
    "Bengali": {
        "primary_reasons": {
            "bank_impersonation": "এই বার্তা ব্যাংকের ছদ্মবেশ ধারণ করে আপনার ব্যক্তিগত তথ্য চাইছে।",
            "urgency_tactic": "এটি তাৎক্ষণিক পদক্ষেপের চাপ তৈরি করছে যা ফিশিংয়ের কৌশল।",
            "credential_request": "এই বার্তা আপনার OTP, পাসওয়ার্ড বা অন্যান্য গোপনীয় তথ্য চাইছে।",
            "suspicious_link": "এতে সন্দেহজনক লিঙ্ক আছে যা আপনাকে নকল ওয়েবসাইটে নিয়ে যেতে পারে।",
            "reward_scam": "এটি একটি নকল পুরস্কার বার্তা যা আপনার তথ্য চুরি করার চেষ্টা করছে।",
            "account_threat": "এই বার্তা আপনার অ্যাকাউন্ট ব্লক করার ভয় দেখাচ্ছে।",
            "safe": "এই বার্তা নিরাপদ বলে মনে হচ্ছে এবং কোনো স্পষ্ট হুমকি নেই।"
        },
        "tactics": {
            "Urgency": "জরুরিত্ব (তাৎক্ষণিক পদক্ষেপের দাবি)",
            "Authority": "কর্তৃত্বের অপব্যবহার (ব্যাংক/সরকারের ছদ্মবেশ)",
            "Fear": "ভয় (অ্যাকাউন্ট বন্ধ হওয়ার হুমকি)",
            "Greed": "লোভ (বিনামূল্যে পুরস্কার/টাকা)"
        },
        "indicators": {
            "Suspicious URL": "সন্দেহজনক ওয়েবসাইট লিঙ্ক",
            "Credential Harvesting Pattern": "ব্যক্তিগত তথ্য চাওয়ার প্যাটার্ন",
            "Misspelled Domain": "ভুল বানানের ডোমেইন",
            "IP Address URL": "IP ঠিকানা লিঙ্ক"
        }
    },
    "Tamil": {
        "primary_reasons": {
            "bank_impersonation": "இந்த செய்தி வங்கியின் போலி வடிவம் எடுத்து உங்கள் தனிப்பட்ட தகவல் கேட்கிறது।",
            "urgency_tactic": "இது உடனடி நடவடிக்கைக்கான அழுத்தத்தை உருவாக்குகிறது, இது ஃபிஷிங் தந்திரம்.",
            "credential_request": "இந்த செய்தி உங்கள் OTP, கடவுச்சொல் அல்லது பிற ரகசிய தகவல்களைக் கேட்கிறது।",
            "suspicious_link": "இதில் சந்தேகத்திற்குரிய இணைப்பு உள்ளது, இது உங்களை போலி வலைதளத்திற்கு அழைத்துச் செல்லலாம்.",
            "reward_scam": "இது போலி பரிசு செய்தி, இது உங்கள் தகவலைத் திருட முயற்சிக்கிறது।",
            "account_threat": "இந்த செய்தி உங்கள் கணக்கை தடுக்க அச்சுறுத்துகிறது.",
            "safe": "இந்த செய்தி பாதுகாப்பானதாகத் தெரிகிறது, எந்த தெளிவான அபாயமும் இல்லை."
        },
        "tactics": {
            "Urgency": "அவசரம் (உடனடி நடவடிக்கை கோரிக்கை)",
            "Authority": "அதிகாரத்தின் துஷ்பிரயோகம் (வங்கி/அரசின் போலி)",
            "Fear": "பயம் (கணக்கு மூடுவதற்கான அச்சுறுத்தல்)",
            "Greed": "பேராசை (இலவச பரிசு/பணம்)"
        },
        "indicators": {
            "Suspicious URL": "சந்தேகத்திற்குரிய வலைத்தள இணைப்பு",
            "Credential Harvesting Pattern": "தனிப்பட்ட தகவல் கோரும் முறை",
            "Misspelled Domain": "தவறான எழுத்துப்பிழை டொமைன்",
            "IP Address URL": "IP முகவரி இணைப்பு"
        }
    },
    "Gujarati": {
        "primary_reasons": {
            "bank_impersonation": "આ સંદેશ બેંકનો નકલી રૂપ ધારણ કરી રહ્યો છે અને તમારી અંગત માહિતી માંગી રહ્યો છે।",
            "urgency_tactic": "આ તાત્કાલિક પગલાં માટે દબાણ બનાવે છે જે ફિશિંગની વ્યૂહરચના છે।",
            "credential_request": "આ સંદેશ તમારો OTP, પાસવર્ડ અથવા અન્ય ગોપનીય માહિતી માંગી રહ્યો છે।",
            "suspicious_link": "આમાં શંકાસ્પદ લિંક છે જે તમને નકલી વેબસાઇટ પર લઈ જઈ શકે છે।",
            "reward_scam": "આ નકલી ઇનામ સંદેશ છે જે તમારી માહિતી ચોરી કરવાનો પ્રયાસ કરી રહ્યો છે।",
            "account_threat": "આ સંદેશ તમારા ખાતાને બ્લોક કરવાની ધમકી આપી રહ્યો છે।",
            "safe": "આ સંદેશ સુરક્ષિત લાગે છે અને કોઈ સ્પષ્ટ જોખમ દેખાતું નથી।"
        },
        "tactics": {
            "Urgency": "તાત્કાલિકતા (તાત્કાલિક પગલાંની માંગ)",
            "Authority": "સત્તાનો દુરુપયોગ (બેંક/સરકારનો નકલી રૂપ)",
            "Fear": "ડર (ખાતું બંધ થવાની ધમકી)",
            "Greed": "લાલચ (મફત ઇનામ/પૈસા)"
        },
        "indicators": {
            "Suspicious URL": "શંકાસ્પદ વેબસાઇટ લિંક",
            "Credential Harvesting Pattern": "અંગત માહિતી માંગવાની પેટર્ન",
            "Misspelled Domain": "ખોટી સ્પેલિંગ ડોમેઇન",
            "IP Address URL": "IP સરનામું લિંક"
        }
    },
    "Malayalam": {
        "primary_reasons": {
            "bank_impersonation": "ഈ സന്ദേശം ബാങ്കിന്റെ വ്യാജ രൂപം സ്വീകരിച്ച് നിങ്ങളുടെ വ്യക്തിഗത വിവരങ്ങൾ ചോദിക്കുന്നു.",
            "urgency_tactic": "ഇത് ഉടനടി നടപടിക്ക് സമ്മർദ്ദം സൃഷ്ടിക്കുന്നു, ഇത് ഫിഷിംഗ് തന്ത്രമാണ്.",
            "credential_request": "ഈ സന്ദേശം നിങ്ങളുടെ OTP, പാസ്വേഡ് അല്ലെങ്കിൽ മറ്റ് രഹസ്യ വിവരങ്ങൾ ചോദിക്കുന്നു.",
            "suspicious_link": "ഇതിൽ സംശയാസ്പദമായ ലിങ്ക് ഉണ്ട്, ഇത് നിങ്ങളെ വ്യാജ വെബ്സൈറ്റിലേക്ക് കൊണ്ടുപോകാം.",
            "reward_scam": "ഇത് വ്യാജ സമ്മാന സന്ദേശമാണ്, ഇത് നിങ്ങളുടെ വിവരങ്ങൾ മോഷ്ടിക്കാൻ ശ്രമിക്കുന്നു.",
            "account_threat": "ഈ സന്ദേശം നിങ്ങളുടെ അക്കൗണ്ട് ബ്ലോക്ക് ചെയ്യുമെന്ന് ഭീഷണിപ്പെടുത്തുന്നു.",
            "safe": "ഈ സന്ദേശം സുരക്ഷിതമാണെന്ന് തോന്നുന്നു, വ്യക്തമായ അപകടമൊന്നുമില്ല."
        },
        "tactics": {
            "Urgency": "അടിയന്തിരത (ഉടനടി നടപടി ആവശ്യം)",
            "Authority": "അധികാരത്തിന്റെ ദുരുപയോഗം (ബാങ്ക്/സർക്കാർ വ്യാജം)",
            "Fear": "ഭയം (അക്കൗണ്ട് അടയ്ക്കൽ ഭീഷണി)",
            "Greed": "അത്യാഗ്രഹം (സൗജന്യ സമ്മാനം/പണം)"
        },
        "indicators": {
            "Suspicious URL": "സംശയാസ്പദമായ വെബ്സൈറ്റ് ലിങ്ക്",
            "Credential Harvesting Pattern": "വ്യക്തിഗത വിവരങ്ങൾ ചോദിക്കുന്ന പാറ്റേൺ",
            "Misspelled Domain": "തെറ്റായ സ്പെല്ലിംഗ് ഡൊമെയ്ൻ",
            "IP Address URL": "IP വിലാസ ലിങ്ക്"
        }
    },
    "English": {
        "primary_reasons": {
            "bank_impersonation": "This message is impersonating a bank and requesting your private information.",
            "urgency_tactic": "This message creates pressure for immediate action, which is a phishing tactic.",
            "credential_request": "This message is asking for your OTP, password, or other confidential information.",
            "suspicious_link": "It contains suspicious links that may redirect you to a fake website.",
            "reward_scam": "This is a fake reward message trying to steal your information.",
            "account_threat": "This message threatens to block your account to scare you.",
            "safe": "This message appears safe and shows no clear threat."
        },
        "tactics": {
            "Urgency": "Urgency (demands immediate action)",
            "Authority": "Authority abuse (impersonating bank/government)",
            "Fear": "Fear (threat of account closure)",
            "Greed": "Greed (free rewards/money)"
        },
        "indicators": {
            "Suspicious URL": "Suspicious website link",
            "Credential Harvesting Pattern": "Pattern requesting private information",
            "Misspelled Domain": "Misspelled domain name",
            "IP Address URL": "IP address link"
        }
    }
}


def get_bilingual_explanation(
    primary_language: str,
    reason_type: str,
    tactics: List[str],
    indicators: List[str]
) -> Dict[str, any]:
    """
    Generate bilingual explanation (vernacular + English).

    Args:
        primary_language: Detected primary language
        reason_type: Type of threat (e.g., "bank_impersonation")
        tactics: List of psychological tactics used
        indicators: List of technical indicators

    Returns:
        {
            "primary_reason": {"en": "...", "vernacular": "..."},
            "psychological_tactics": [{"en": "...", "vernacular": "..."}],
            "technical_indicators": [{"en": "...", "vernacular": "..."}]
        }
    """
    # Default to English if language not supported
    if primary_language not in EXPLANATIONS:
        primary_language = "English"

    vernacular_data = EXPLANATIONS[primary_language]
    english_data = EXPLANATIONS["English"]

    # Get primary reason
    primary_reason_en = english_data["primary_reasons"].get(reason_type,
        english_data["primary_reasons"]["safe"])
    primary_reason_vn = vernacular_data["primary_reasons"].get(reason_type,
        vernacular_data["primary_reasons"]["safe"])

    # Get tactics translations
    tactics_bilingual = []
    for tactic in tactics:
        tactic_en = english_data["tactics"].get(tactic, tactic)
        tactic_vn = vernacular_data["tactics"].get(tactic, tactic)
        tactics_bilingual.append({
            "en": tactic_en,
            "vernacular": tactic_vn
        })

    # Get indicators translations
    indicators_bilingual = []
    for indicator in indicators:
        indicator_en = english_data["indicators"].get(indicator, indicator)
        indicator_vn = vernacular_data["indicators"].get(indicator, indicator)
        indicators_bilingual.append({
            "en": indicator_en,
            "vernacular": indicator_vn
        })

    return {
        "primary_reason": {
            "en": primary_reason_en,
            "vernacular": primary_reason_vn,
            "language": primary_language
        },
        "psychological_tactics": tactics_bilingual,
        "technical_indicators": indicators_bilingual
    }


def determine_reason_type(signals: List[str], has_links: bool) -> str:
    """Determine the type of threat based on signals."""
    signals_str = " ".join(signals).lower()

    if "impersonation" in signals_str or "brand" in signals_str:
        return "bank_impersonation"
    elif "urgency" in signals_str and "credential" in signals_str:
        return "urgency_tactic"
    elif "credential" in signals_str:
        return "credential_request"
    elif has_links and ("suspicious" in signals_str or "url" in signals_str):
        return "suspicious_link"
    elif "reward" in signals_str or "prize" in signals_str:
        return "reward_scam"
    elif "block" in signals_str or "suspend" in signals_str:
        return "account_threat"
    else:
        return "safe"
