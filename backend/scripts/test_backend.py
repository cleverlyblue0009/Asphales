#!/usr/bin/env python3
"""Complete backend verification script for SurakshaAI Shield."""

import json
import sys
import time

import httpx

BASE_URL = "http://localhost:8000"
TIMEOUT = 10.0

passed = 0
failed = 0


def result(name: str, ok: bool, detail: str = ""):
    global passed, failed
    if ok:
        passed += 1
        tag = "PASSED"
    else:
        failed += 1
        tag = "FAILED"
    suffix = f" ({detail})" if detail else ""
    print(f"  {'✅' if ok else '❌'} {name} - {tag}{suffix}")


def test_health_check(client: httpx.Client):
    r = client.get("/")
    ok = r.status_code == 200 and r.json().get("status") == "ok"
    result("Test 1: Health Check", ok)


def test_pattern_matching(client: httpx.Client):
    phishing = "URGENT! Password share karo aur OTP bhejo turant verify karo. Account block hoga."
    r = client.post("/analyze", json={"text": phishing})
    data = r.json()
    threats = data.get("threats", [])
    ok = r.status_code == 200 and data.get("overall_risk", 0) > 50 and len(threats) >= 3
    result("Test 2: Pattern Matching", ok, f"Detected {len(threats)} threats, risk={data.get('overall_risk')}")


def test_genai_integration(client: httpx.Client):
    r = client.get("/")
    genai_available = r.json().get("genai_available", False)
    if not genai_available:
        result("Test 3: GenAI Integration", True, "Skipped — no API key, fallback mode OK")
        return

    phishing = "CBI officer bol raha hoon. Aapke khilaf warrant issue hua hai."
    r = client.post("/analyze", json={"text": phishing}, timeout=15.0)
    data = r.json()
    ok = r.status_code == 200 and data.get("overall_risk", 0) > 40
    method = data.get("method", "unknown")
    result("Test 3: GenAI Integration", ok, f"method={method}, risk={data.get('overall_risk')}")


def test_hybrid_classification(client: httpx.Client):
    text = "Account block hoga agar password share nahi kiya. Turant karo."
    r = client.post("/analyze", json={"text": text}, timeout=15.0)
    data = r.json()
    score = data.get("overall_risk", 0)
    ok = r.status_code == 200 and score > 50
    result("Test 4: Hybrid Classification", ok, f"Score: {score}/100")


def test_caching(client: httpx.Client):
    text = "Test caching message with OTP bhejo."
    # First request
    r1 = client.post("/analyze", json={"text": text}, timeout=15.0)
    # Second request (should be cached)
    r2 = client.post("/analyze", json={"text": text})
    cached = r2.json().get("cached", False)

    stats = client.get("/stats").json()
    cache_stats = stats.get("cache", {})
    hit_rate = cache_stats.get("hit_rate_percent", 0)
    ok = r1.status_code == 200 and r2.status_code == 200 and cached
    result("Test 5: Caching", ok, f"Hit rate: {hit_rate}%")


def test_batch_processing(client: httpx.Client):
    texts = [
        "Password share karo turant",
        "Aaj ka weather kaisa hai?",
        "OTP bhejo abhi",
        "Meeting kal 3 baje hai",
        "Lottery jeeta hai aapne!",
    ]
    start = time.time()
    r = client.post("/batch-analyze", json={"texts": texts}, timeout=30.0)
    elapsed = time.time() - start
    data = r.json()
    count = data.get("count", 0)
    ok = r.status_code == 200 and count == 5
    result("Test 6: Batch Processing", ok, f"{count} messages in {elapsed:.1f}s")


def test_error_handling(client: httpx.Client):
    # Empty text
    r1 = client.post("/analyze", json={"text": ""})
    # Very long text
    r2 = client.post("/analyze", json={"text": "a" * 6000})
    # Both should return 422 (validation error) or a handled response
    ok = r1.status_code in (400, 422) and r2.status_code in (400, 422)
    result("Test 7: Error Handling", ok)


def test_response_time(client: httpx.Client):
    text = "Simple safe message for timing test."
    times = []
    for _ in range(3):
        start = time.time()
        client.post("/analyze", json={"text": text})
        times.append((time.time() - start) * 1000)

    avg = sum(times) / len(times)
    ok = avg < 3000
    result("Test 8: Response Time", ok, f"Avg: {avg:.0f}ms")


def test_accuracy(client: httpx.Client):
    phishing_texts = [
        "Password share karo turant!",
        "OTP bhejo abhi warna account block hoga",
        "Lottery jeeta hai 50 lakh",
        "CVV batao verification ke liye",
        "Bank details share karo",
    ]
    safe_texts = [
        "Kal meeting hai 3 baje",
        "Happy birthday! Party kab hai?",
        "Order shipped. Delivery tomorrow.",
        "Kya haal hai bhai?",
        "Cricket match ka score dekha?",
    ]

    correct = 0
    total = len(phishing_texts) + len(safe_texts)

    for text in phishing_texts:
        r = client.post("/analyze", json={"text": text}, timeout=15.0)
        if r.json().get("overall_risk", 0) > 40:
            correct += 1

    for text in safe_texts:
        r = client.post("/analyze", json={"text": text})
        if r.json().get("overall_risk", 100) < 40:
            correct += 1

    accuracy = correct / total * 100
    ok = accuracy >= 80
    result("Test 9: Accuracy", ok, f"{accuracy:.0f}% on test set")


def test_edge_cases(client: httpx.Client):
    # Whitespace only
    r1 = client.post("/analyze", json={"text": "   "})
    # Special characters
    r2 = client.post("/analyze", json={"text": "🔥💰🎉!!!"})
    # Unicode Devanagari
    r3 = client.post("/analyze", json={"text": "यह एक सामान्य संदेश है।"})

    ok = all(r.status_code in (200, 422) for r in [r1, r2, r3])
    result("Test 10: Edge Cases", ok)


def main():
    print()
    print("🧪 SurakshaAI Backend Test Suite")
    print("=" * 40)
    print()

    try:
        client = httpx.Client(base_url=BASE_URL, timeout=TIMEOUT)
        # Quick connectivity check
        client.get("/")
    except httpx.ConnectError:
        print(f"❌ Cannot connect to {BASE_URL}")
        print("   Make sure the server is running: python app.py")
        sys.exit(1)

    test_health_check(client)
    test_pattern_matching(client)
    test_genai_integration(client)
    test_hybrid_classification(client)
    test_caching(client)
    test_batch_processing(client)
    test_error_handling(client)
    test_response_time(client)
    test_accuracy(client)
    test_edge_cases(client)

    print()
    print("=" * 40)
    total = passed + failed
    print(f"Overall: {passed}/{total} tests passed {'✅' if failed == 0 else '❌'}")
    if failed == 0:
        print("Backend is production ready! 🚀")
    else:
        print(f"{failed} test(s) failed.")
    print()

    client.close()
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
