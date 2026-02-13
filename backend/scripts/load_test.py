#!/usr/bin/env python3
"""Load testing script for SurakshaAI Shield backend."""

import statistics
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import httpx

BASE_URL = "http://localhost:8000"

MESSAGES = [
    "Password share karo turant!",
    "OTP bhejo abhi",
    "Kal meeting hai 3 baje",
    "Lottery jeeta hai 50 lakh",
    "Kya haal hai bhai?",
    "Account block hoga",
    "CVV batao",
    "Happy birthday!",
    "Bank details share karo",
    "Cricket match dekhne chalein?",
]


def send_request(client: httpx.Client, text: str) -> tuple[int, float]:
    """Send a single analyze request. Returns (status_code, latency_ms)."""
    start = time.time()
    try:
        r = client.post("/analyze", json={"text": text}, timeout=15.0)
        return r.status_code, (time.time() - start) * 1000
    except Exception:
        return 0, (time.time() - start) * 1000


def main():
    print("\n⚡ SurakshaAI Load Test")
    print("=" * 40)

    try:
        httpx.get(f"{BASE_URL}/", timeout=5.0)
    except httpx.ConnectError:
        print(f"\n❌ Cannot connect to {BASE_URL}")
        sys.exit(1)

    # Sequential: 100 requests
    print("\n  Phase 1: 100 sequential requests...")
    client = httpx.Client(base_url=BASE_URL, timeout=15.0)
    latencies = []
    errors = 0
    for i in range(100):
        text = MESSAGES[i % len(MESSAGES)]
        status, ms = send_request(client, text)
        latencies.append(ms)
        if status != 200:
            errors += 1

    print(f"    Requests:  100")
    print(f"    Errors:    {errors}")
    print(f"    Avg:       {statistics.mean(latencies):.0f}ms")
    print(f"    Median:    {statistics.median(latencies):.0f}ms")
    print(f"    p95:       {sorted(latencies)[94]:.0f}ms")
    print(f"    p99:       {sorted(latencies)[98]:.0f}ms")

    # Concurrent: 10 simultaneous
    print("\n  Phase 2: 10 concurrent requests...")
    concurrent_latencies = []
    concurrent_errors = 0

    with ThreadPoolExecutor(max_workers=10) as pool:
        futures = [
            pool.submit(send_request, client, MESSAGES[i % len(MESSAGES)])
            for i in range(10)
        ]
        for f in as_completed(futures):
            status, ms = f.result()
            concurrent_latencies.append(ms)
            if status != 200:
                concurrent_errors += 1

    print(f"    Requests:  10")
    print(f"    Errors:    {concurrent_errors}")
    print(f"    Avg:       {statistics.mean(concurrent_latencies):.0f}ms")
    print(f"    Max:       {max(concurrent_latencies):.0f}ms")

    # Cache stats
    print("\n  Phase 3: Cache performance...")
    stats_r = client.get("/stats")
    cache = stats_r.json().get("cache", {})
    print(f"    Cache size: {cache.get('size', 0)}")
    print(f"    Hit rate:   {cache.get('hit_rate_percent', 0)}%")
    print(f"    Hits:       {cache.get('hits', 0)}")
    print(f"    Misses:     {cache.get('misses', 0)}")

    client.close()

    print("\n" + "=" * 40)
    all_ok = errors == 0 and concurrent_errors == 0
    print(f"Load test {'PASSED ✅' if all_ok else 'COMPLETED with errors ⚠️'}\n")


if __name__ == "__main__":
    main()
