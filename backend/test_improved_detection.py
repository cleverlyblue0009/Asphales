#!/usr/bin/env python3
"""Test the improved phishing detection with bilingual support and reduced false positives."""

import asyncio
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from api.routes import set_classifier, analyze_text, AnalyzeRequest
from services.classifier import HybridClassifier


# Test cases covering the issues mentioned
TEST_CASES = [
    {
        "name": "Benign Educational Content (VIT Vellore)",
        "text": "VIT Vellore Freshers 2024 - Welcome to campus! Orientation schedule and important dates.",
        "expected_risk": "LOW RISK",
        "should_highlight": False
    },
    {
        "name": "Benign Sports Content (Format: Swiss Style)",
        "text": "Format: Swiss Style. 7 rounds. Tournament schedule posted below. Good luck to all players!",
        "expected_risk": "LOW RISK",
        "should_highlight": False
    },
    {
        "name": "Benign Project Discussion",
        "text": "Class project deadline extended to next Friday. Please submit your assignments on time.",
        "expected_risk": "LOW RISK",
        "should_highlight": False
    },
    {
        "name": "Hindi Phishing - Bank Threat",
        "text": "आपका बैंक खाता बंद कर दिया गया है। तुरंत सत्यापन करें। http://fake-bank.suspicious.com",
        "expected_risk": "HIGH RISK",
        "should_highlight": True,
        "expected_language": "Hindi"
    },
    {
        "name": "Hindi Phishing - Reward Scam",
        "text": "बधाई हो! आपने ₹50,000 का इनाम जीता है! अभी दावा करें: http://reward-claim.xyz",
        "expected_risk": "HIGH RISK",
        "should_highlight": True,
        "expected_language": "Hindi"
    },
    {
        "name": "Bengali Phishing - KYC Scam",
        "text": "আপনার UPI KYC সম্পন্ন করুন এখনই। না হলে আপনার অ্যাকাউন্ট ব্লক হবে। http://upi-kyc-verify.link",
        "expected_risk": "HIGH RISK",
        "should_highlight": True,
        "expected_language": "Bengali"
    },
    {
        "name": "Tamil Safe Message",
        "text": "இன்று மாலை கூட்டம் 5 மணிக்கு. அனைவரும் கலந்து கொள்ளுங்கள்.",
        "expected_risk": "LOW RISK",
        "should_highlight": False,
        "expected_language": "Tamil"
    },
    {
        "name": "English Phishing - Credential Theft",
        "text": "Your bank account will be blocked! Click here immediately to verify OTP and password: http://secure-verify.tk",
        "expected_risk": "HIGH RISK",
        "should_highlight": True
    },
    {
        "name": "Mixed Content - Educational with Keywords",
        "text": "VIT University admission notice: Format - Online. Password for portal will be sent via email. Check your inbox.",
        "expected_risk": "LOW RISK",
        "should_highlight": False
    },
    {
        "name": "Gujarati Safe Message",
        "text": "આજે ક્લાસ કેટલા વાગ્યે શરૂ થશે? તું ઘરે સુરક્ષિત પહોંચી ગયો?",
        "expected_risk": "LOW RISK",
        "should_highlight": False,
        "expected_language": "Gujarati"
    }
]


async def run_tests():
    """Run all test cases and print results."""
    print("=" * 80)
    print("Testing Improved Phishing Detection with Bilingual Support")
    print("=" * 80)
    print()

    # Initialize classifier
    classifier = HybridClassifier()
    set_classifier(classifier)

    passed = 0
    failed = 0

    for i, test_case in enumerate(TEST_CASES, 1):
        print(f"\n{'=' * 80}")
        print(f"Test {i}/{len(TEST_CASES)}: {test_case['name']}")
        print(f"{'=' * 80}")
        print(f"Text: {test_case['text'][:100]}{'...' if len(test_case['text']) > 100 else ''}")
        print()

        # Run analysis
        request = AnalyzeRequest(text=test_case["text"])
        result = await analyze_text(request)

        # Extract results
        risk_level = result.get("risk_level", "UNKNOWN")
        risk_score = result.get("risk_score", 0.0)
        harmful_links = result.get("harmful_links", [])
        explanation = result.get("structured_explanation", {})
        language_info = result.get("language_info", {})
        suspicious_segments = result.get("suspicious_segments", [])

        detected_lang = language_info.get("primary_language", "Unknown")
        primary_reason = explanation.get("primary_reason", "N/A")
        primary_reason_vn = explanation.get("primary_reason_vernacular", "N/A")
        tactics = explanation.get("psychological_tactics", [])
        tactics_vn = explanation.get("psychological_tactics_vernacular", [])
        indicators = explanation.get("technical_indicators", [])

        # Check test expectations
        risk_match = risk_level == test_case["expected_risk"]
        highlight_match = (len(suspicious_segments) > 0) == test_case["should_highlight"]
        lang_match = (
            "expected_language" not in test_case or
            detected_lang == test_case["expected_language"]
        )

        test_passed = risk_match and highlight_match and lang_match

        if test_passed:
            passed += 1
            status = "✓ PASS"
            color = "\033[92m"  # Green
        else:
            failed += 1
            status = "✗ FAIL"
            color = "\033[91m"  # Red

        reset_color = "\033[0m"

        print(f"Status: {color}{status}{reset_color}")
        print(f"\nResults:")
        print(f"  Risk Level: {risk_level} (Expected: {test_case['expected_risk']}) {'✓' if risk_match else '✗'}")
        print(f"  Risk Score: {risk_score:.3f} ({risk_score * 100:.1f}%)")
        print(f"  Should Highlight: {test_case['should_highlight']} | Highlighted: {len(suspicious_segments) > 0} {'✓' if highlight_match else '✗'}")
        print(f"  Detected Language: {detected_lang}", end="")
        if "expected_language" in test_case:
            print(f" (Expected: {test_case['expected_language']}) {'✓' if lang_match else '✗'}", end="")
        print()

        print(f"\nExplanation:")
        print(f"  Primary Reason (EN): {primary_reason}")
        if primary_reason_vn and primary_reason_vn != primary_reason:
            print(f"  Primary Reason ({detected_lang}): {primary_reason_vn}")

        if tactics:
            print(f"  Tactics (EN): {', '.join(tactics)}")
            if tactics_vn:
                print(f"  Tactics ({detected_lang}): {', '.join(tactics_vn)}")

        if indicators:
            print(f"  Technical Indicators: {', '.join(indicators)}")

        if harmful_links:
            print(f"  Harmful Links: {len(harmful_links)}")
            for link in harmful_links[:3]:
                print(f"    - {link}")

        if suspicious_segments:
            print(f"  Suspicious Segments: {len(suspicious_segments)}")
            for seg in suspicious_segments[:2]:
                print(f"    - {seg['phrase'][:60]}... (Risk: {seg['risk_score'] * 100:.0f}%)")

    print(f"\n{'=' * 80}")
    print(f"Test Summary: {passed} PASSED, {failed} FAILED out of {len(TEST_CASES)} tests")
    print(f"Success Rate: {passed / len(TEST_CASES) * 100:.1f}%")
    print(f"{'=' * 80}\n")

    return failed == 0


if __name__ == "__main__":
    success = asyncio.run(run_tests())
    sys.exit(0 if success else 1)
