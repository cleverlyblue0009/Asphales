#!/usr/bin/env python3
"""Test GenAI (Claude API) integration for SurakshaAI Shield."""

import json
import os
import sys

# Add parent directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from dotenv import load_dotenv

load_dotenv()

import anthropic


def main():
    print("\n🤖 SurakshaAI GenAI Integration Test")
    print("=" * 40)

    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key or api_key.startswith("sk-ant-api03-xxxxx"):
        print("\n❌ No valid ANTHROPIC_API_KEY found in environment.")
        print("   Set it with: export ANTHROPIC_API_KEY='your-key-here'")
        print("   Skipping GenAI tests — pattern-only mode still works.\n")
        sys.exit(0)

    print(f"\n  API Key: {api_key[:12]}...{api_key[-4:]}")

    client = anthropic.Anthropic(api_key=api_key, timeout=10)

    # Test 1: API key validity
    print("\n  Testing API key validity...")
    try:
        response = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=64,
            messages=[{"role": "user", "content": "Say 'ok' and nothing else."}],
        )
        text = response.content[0].text.strip()
        print(f"  ✅ API key is valid — response: {text}")
    except anthropic.AuthenticationError:
        print("  ❌ API key is invalid")
        sys.exit(1)
    except Exception as exc:
        print(f"  ❌ API error: {exc}")
        sys.exit(1)

    # Test 2: Phishing detection prompt
    print("\n  Testing phishing detection prompt...")
    test_msg = "URGENT! Aapke account mein fraud hua hai. Turant OTP share karo warna account block ho jayega."
    try:
        response = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=512,
            system="You are a phishing detector. Respond with JSON only: {\"risk_score\": int, \"is_phishing\": bool, \"tactics\": [str], \"explanation_hinglish\": str, \"confidence\": float}",
            messages=[{"role": "user", "content": f'Analyze this message for phishing:\n\n"{test_msg}"\n\nRespond with JSON only.'}],
        )
        raw = response.content[0].text.strip()
        if raw.startswith("```"):
            lines = raw.split("\n")
            raw = "\n".join(lines[1:-1])
        result = json.loads(raw)
        print(f"  ✅ Phishing detection works")
        print(f"     Risk score: {result.get('risk_score')}")
        print(f"     Is phishing: {result.get('is_phishing')}")
        print(f"     Tactics: {result.get('tactics')}")
        print(f"     Explanation: {result.get('explanation_hinglish', '')[:100]}")
    except json.JSONDecodeError:
        print(f"  ⚠️  Response not valid JSON: {raw[:200]}")
    except Exception as exc:
        print(f"  ❌ Error: {exc}")

    # Test 3: Safe message
    print("\n  Testing safe message detection...")
    safe_msg = "Kal meeting hai office mein 3 baje. Please time pe aana."
    try:
        response = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=512,
            system="You are a phishing detector. Respond with JSON only: {\"risk_score\": int, \"is_phishing\": bool, \"tactics\": [str], \"explanation_hinglish\": str, \"confidence\": float}",
            messages=[{"role": "user", "content": f'Analyze this message for phishing:\n\n"{safe_msg}"\n\nRespond with JSON only.'}],
        )
        raw = response.content[0].text.strip()
        if raw.startswith("```"):
            lines = raw.split("\n")
            raw = "\n".join(lines[1:-1])
        result = json.loads(raw)
        risk = result.get("risk_score", 100)
        print(f"  ✅ Safe message classified — risk_score: {risk}")
        if risk < 30:
            print("     Correctly identified as safe")
        else:
            print("     ⚠️  Risk higher than expected for safe message")
    except Exception as exc:
        print(f"  ❌ Error: {exc}")

    # Test 4: Code-mixed Hinglish
    print("\n  Testing code-mixed Hinglish handling...")
    hinglish = "Bhai, cricket match ka score dekha? India jeet gayi!"
    try:
        response = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=512,
            system="You are a phishing detector. Respond with JSON only: {\"risk_score\": int, \"is_phishing\": bool, \"tactics\": [str], \"explanation_hinglish\": str, \"confidence\": float}",
            messages=[{"role": "user", "content": f'Analyze this message for phishing:\n\n"{hinglish}"\n\nRespond with JSON only.'}],
        )
        raw = response.content[0].text.strip()
        if raw.startswith("```"):
            lines = raw.split("\n")
            raw = "\n".join(lines[1:-1])
        result = json.loads(raw)
        print(f"  ✅ Hinglish handling works — risk_score: {result.get('risk_score')}")
    except Exception as exc:
        print(f"  ❌ Error: {exc}")

    print("\n" + "=" * 40)
    print("GenAI integration tests complete.\n")


if __name__ == "__main__":
    main()
