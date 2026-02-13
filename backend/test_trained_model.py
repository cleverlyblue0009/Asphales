#!/usr/bin/env python3
"""Test the trained models with sample messages."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from services.ml_classifier import MLPhishingClassifier

# Test messages (safe and threat examples)
test_messages = [
    # Safe messages
    {
        "text": "आज क्लास कितने बजे शुरू होगी?",
        "expected": "safe",
        "language": "Hindi"
    },
    {
        "text": "मैं शाम को बाजार जा रहा हूँ, कुछ चाहिए?",
        "expected": "safe",
        "language": "Hindi"
    },
    {
        "text": "ഇന്ന് ക്ലാസ് എപ്പോഴാണ് തുടങ്ങുന്നത്?",
        "expected": "safe",
        "language": "Malayalam"
    },
    # Threat messages
    {
        "text": "आपका बैंक खाता बंद कर दिया गया है। तुरंत सत्यापन करें।",
        "expected": "threat",
        "language": "Hindi"
    },
    {
        "text": "आपने ₹25,000 का इनाम जीता है! अभी दावा करें।",
        "expected": "threat",
        "language": "Hindi"
    },
    {
        "text": "താങ്കളുടെ ബാങ്ക് അക്കൗണ്ട് സസ്പെൻഡ് ചെയ്തിരിക്കുന്നു. ഉടൻ സ്ഥിരീകരിക്കുക.",
        "expected": "threat",
        "language": "Malayalam"
    },
    {
        "text": "તમારું બેંક એકાઉન્ટ તાત્કાલિક બંધ કરવામાં આવ્યું છે. તરત જ ચકાસણી કરો.",
        "expected": "threat",
        "language": "Gujarati"
    },
]

def main():
    print("Testing trained ML model...\n")
    print("=" * 80)

    # Initialize classifier
    clf = MLPhishingClassifier()

    correct = 0
    total = len(test_messages)

    for i, msg in enumerate(test_messages, 1):
        result = clf.predict(msg["text"])

        is_correct = (result["is_phishing"] and msg["expected"] == "threat") or \
                    (not result["is_phishing"] and msg["expected"] == "safe")

        status = "✓" if is_correct else "✗"
        if is_correct:
            correct += 1

        print(f"\nTest {i}/{total} [{status}]")
        print(f"Language: {msg['language']}")
        print(f"Text: {msg['text'][:60]}...")
        print(f"Expected: {msg['expected']}")
        print(f"Predicted: {'threat' if result['is_phishing'] else 'safe'}")
        print(f"Risk Score: {result['risk_score']:.3f}")
        print(f"Confidence: {result['confidence']:.3f}")
        print("-" * 80)

    print(f"\n{'=' * 80}")
    print(f"Results: {correct}/{total} correct ({100 * correct / total:.1f}%)")
    print(f"{'=' * 80}\n")

if __name__ == "__main__":
    main()
