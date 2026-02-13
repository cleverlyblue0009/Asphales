#!/usr/bin/env python3
"""Test language detection and bilingual explanation generation."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from utils.language_detector import (
    detect_language,
    get_primary_language,
    get_language_info,
    count_threat_keywords,
    count_safe_keywords
)
from utils.bilingual_explainer import (
    get_bilingual_explanation,
    determine_reason_type
)


TEST_TEXTS = [
    {
        "text": "आपका बैंक खाता बंद कर दिया गया है। तुरंत सत्यापन करें।",
        "expected_lang": "Hindi",
        "description": "Hindi phishing message"
    },
    {
        "text": "VIT Vellore Freshers 2024 - Welcome to campus!",
        "expected_lang": "English",
        "description": "English educational content"
    },
    {
        "text": "আপনার UPI KYC সম্পন্ন করুন এখনই। না হলে আপনার অ্যাকাউন্ট ব্লক হবে।",
        "expected_lang": "Bengali",
        "description": "Bengali phishing message"
    },
    {
        "text": "இன்று மாலை கூட்டம் 5 மணிக்கு. அனைவரும் கலந்து கொள்ளுங்கள்.",
        "expected_lang": "Tamil",
        "description": "Tamil safe message"
    },
    {
        "text": "Class project deadline extended. Please submit by Friday.",
        "expected_lang": "English",
        "description": "English benign message"
    }
]


def test_language_detection():
    """Test language detection functionality."""
    print("=" * 80)
    print("Testing Language Detection")
    print("=" * 80)
    print()

    passed = 0
    total = len(TEST_TEXTS)

    for i, test in enumerate(TEST_TEXTS, 1):
        print(f"\nTest {i}/{total}: {test['description']}")
        print(f"Text: {test['text'][:60]}...")

        # Detect language
        detected_langs = detect_language(test['text'])
        primary_lang = get_primary_language(test['text'])
        lang_info = get_language_info(test['text'])

        threat_count = count_threat_keywords(test['text'])
        safe_count = count_safe_keywords(test['text'])

        # Check if primary language matches
        match = primary_lang == test['expected_lang']
        if match:
            passed += 1
            print(f"✓ PASS - Detected: {primary_lang}")
        else:
            print(f"✗ FAIL - Detected: {primary_lang}, Expected: {test['expected_lang']}")

        print(f"  All languages: {', '.join(f'{lang} ({count} chars)' for lang, count in detected_langs[:3])}")
        print(f"  Threat keywords: {threat_count}")
        print(f"  Safe keywords: {safe_count}")
        print(f"  Likely benign: {lang_info.get('likely_benign', False)}")

    print(f"\n{'=' * 80}")
    print(f"Language Detection: {passed}/{total} tests passed ({passed/total*100:.1f}%)")
    print(f"{'=' * 80}\n")

    return passed == total


def test_bilingual_explanations():
    """Test bilingual explanation generation."""
    print("=" * 80)
    print("Testing Bilingual Explanation Generation")
    print("=" * 80)
    print()

    test_cases = [
        {
            "language": "Hindi",
            "reason_type": "bank_impersonation",
            "tactics": ["Urgency", "Authority"],
            "indicators": ["Suspicious URL", "Credential Harvesting Pattern"]
        },
        {
            "language": "Bengali",
            "reason_type": "urgency_tactic",
            "tactics": ["Urgency", "Fear"],
            "indicators": ["Credential Harvesting Pattern"]
        },
        {
            "language": "English",
            "reason_type": "credential_request",
            "tactics": ["Fear"],
            "indicators": ["Suspicious URL"]
        }
    ]

    for i, test in enumerate(test_cases, 1):
        print(f"\nTest {i}: {test['language']} - {test['reason_type']}")

        explanation = get_bilingual_explanation(
            test['language'],
            test['reason_type'],
            test['tactics'],
            test['indicators']
        )

        print(f"  Primary Reason (EN): {explanation['primary_reason']['en']}")
        print(f"  Primary Reason ({test['language']}): {explanation['primary_reason']['vernacular']}")

        if explanation['psychological_tactics']:
            print(f"  Tactics:")
            for tactic in explanation['psychological_tactics']:
                print(f"    - {tactic['en']} | {tactic['vernacular']}")

        if explanation['technical_indicators']:
            print(f"  Indicators:")
            for indicator in explanation['technical_indicators']:
                print(f"    - {indicator['en']} | {indicator['vernacular']}")

    print(f"\n{'=' * 80}")
    print("Bilingual Explanation Generation: ✓ PASS")
    print(f"{'=' * 80}\n")

    return True


if __name__ == "__main__":
    test1 = test_language_detection()
    test2 = test_bilingual_explanations()

    print("\n" + "=" * 80)
    print("Overall Test Results:")
    print(f"  Language Detection: {'✓ PASS' if test1 else '✗ FAIL'}")
    print(f"  Bilingual Explanations: {'✓ PASS' if test2 else '✗ FAIL'}")
    print("=" * 80 + "\n")

    sys.exit(0 if (test1 and test2) else 1)
