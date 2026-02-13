"""Build multilingual phishing datasets with adversarial and contextual variants."""

from __future__ import annotations

import argparse
import csv
import random
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

RANDOM_SEED = 42

ADVERSARIAL_MAP = {
    "verify": "ver1fy",
    "account": "acc0unt",
    "urgent": "urg3nt",
    "update": "upd4te",
    "security": "s3curity",
    "password": "passw0rd",
    "bank": "b4nk",
}

PHISHING_TEMPLATES = [
    "{bank} alert: Your {account_word} will be blocked in 2 hours. {verify_word} now: {link}",
    "Urgent KYC failure detected. {update_word} immediately at {link} to avoid suspension.",
    "Dear customer, suspicious login detected. Reset {password_word} here: {link}",
    "{bank} notice: claim refund now, confirm card details at {link}",
    "Final warning: your wallet is frozen. Reactivate through {link}",
]

LEGIT_TEMPLATES = [
    "{bank}: Your monthly statement is ready in the secure app inbox.",
    "Transaction alert: INR 1,250 spent on UPI. If not you, contact helpline.",
    "EMI reminder: payment due on 5th, no action needed if already paid.",
    "Security tip from {bank}: never share OTP, PIN or password with anyone.",
]

NEUTRAL_FINANCE = [
    "Gold prices closed 0.4% higher in today's market report.",
    "RBI policy update kept repo rate unchanged.",
    "Mutual fund SIPs continue to grow among salaried users.",
    "Quarterly results indicate stable banking sector growth.",
]

MULTILINGUAL_PHISHING = [
    "तुरंत ver1fy करें नहीं तो acc0unt बंद होगा: {link}",
    "உங்கள் acc0unt முடக்கப்படும், urg3nt update செய்யவும் {link}",
    "আপনার acc0unt suspend হবে, এখনই ver1fy করুন {link}",
    "Bank se message: urg3nt KYC update warna account block {link}",
]

SUSPICIOUS_LINKS = [
    "http://185.66.9.44/secure-login",
    "https://secure-verification.top/update",
    "http://bit.ly/3kYcNow",
    "https://acc-verify.xyz/otp-check",
    "http://tinyurl.com/reverify-bank",
]

SAFE_LINKS = [
    "https://www.onlinesbi.sbi/",
    "https://www.hdfcbank.com/",
    "https://www.icicibank.com/",
]

BANKS = ["SBI", "HDFC", "ICICI", "Axis Bank"]


@dataclass
class Sample:
    text: str
    label: int
    category: str


def apply_adversarial_noise(text: str, rng: random.Random, p: float = 0.45) -> str:
    out = text
    for src, dst in ADVERSARIAL_MAP.items():
        if rng.random() < p:
            out = re.sub(rf"\b{re.escape(src)}\b", dst, out, flags=re.IGNORECASE)
    return out


def build_phishing_samples(count: int, rng: random.Random) -> list[Sample]:
    samples: list[Sample] = []
    for _ in range(count):
        template = rng.choice(PHISHING_TEMPLATES + MULTILINGUAL_PHISHING)
        sample = template.format(
            bank=rng.choice(BANKS),
            account_word="account",
            verify_word="verify",
            update_word="update",
            password_word="password",
            link=rng.choice(SUSPICIOUS_LINKS),
        )
        if rng.random() < 0.7:
            sample = apply_adversarial_noise(sample, rng)
        samples.append(Sample(text=sample, label=1, category="phishing"))
    return samples


def build_legit_samples(count: int, rng: random.Random) -> list[Sample]:
    samples: list[Sample] = []
    for _ in range(count):
        bank = rng.choice(BANKS)
        pool = LEGIT_TEMPLATES + NEUTRAL_FINANCE
        text = rng.choice(pool).format(bank=bank)
        if rng.random() < 0.25:
            text = f"{text} More details: {rng.choice(SAFE_LINKS)}"
        samples.append(Sample(text=text, label=0, category="legitimate"))
    return samples


def stratified_split(samples: Iterable[Sample], test_size: float, rng: random.Random) -> tuple[list[Sample], list[Sample]]:
    phishing = [s for s in samples if s.label == 1]
    legit = [s for s in samples if s.label == 0]
    rng.shuffle(phishing)
    rng.shuffle(legit)

    p_test = int(len(phishing) * test_size)
    l_test = int(len(legit) * test_size)

    test = phishing[:p_test] + legit[:l_test]
    train = phishing[p_test:] + legit[l_test:]
    rng.shuffle(train)
    rng.shuffle(test)
    return train, test


def write_csv(path: Path, rows: list[Sample]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["text", "label", "category"])
        writer.writeheader()
        for row in rows:
            writer.writerow({"text": row.text, "label": row.label, "category": row.category})


def build_dataset(total_samples: int, test_size: float, output_dir: Path) -> None:
    rng = random.Random(RANDOM_SEED)
    phishing_n = total_samples // 2
    legit_n = total_samples - phishing_n

    samples = build_phishing_samples(phishing_n, rng) + build_legit_samples(legit_n, rng)
    train, test = stratified_split(samples, test_size=test_size, rng=rng)

    write_csv(output_dir / "train.csv", train)
    write_csv(output_dir / "test.csv", test)
    write_csv(output_dir / "full_dataset.csv", samples)

    print(f"Built dataset in {output_dir}")
    print(f"Train: {len(train)} | Test: {len(test)} | Total: {len(samples)}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate multilingual phishing dataset")
    parser.add_argument("--total-samples", type=int, default=8000)
    parser.add_argument("--test-size", type=float, default=0.2)
    parser.add_argument("--output-dir", type=Path, default=Path("data/engineered"))
    args = parser.parse_args()
    build_dataset(total_samples=args.total_samples, test_size=args.test_size, output_dir=args.output_dir)
