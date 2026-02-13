"""Pure-Python ML phishing classifier (multinomial Naive Bayes)."""

from __future__ import annotations

import csv
import json
import math
import re
from collections import Counter
from pathlib import Path

from utils.logger import setup_logger

logger = setup_logger("ml_classifier")

BASE_DIR = Path(__file__).resolve().parents[1]
DATASET_PATH = BASE_DIR / "data" / "phishing_multilingual_7500.csv"
MODEL_PATH = BASE_DIR / "models" / "phishing_nb_model.json"
TOKEN_RE = re.compile(r"\w+", re.UNICODE)


class MLPhishingClassifier:
    """Multinomial Naive Bayes over multilingual tokens."""

    def __init__(self):
        self.model_name = "multinomial-naive-bayes-token"
        self.model: dict = {}
        self._load_or_train()

    def _load_or_train(self) -> None:
        if MODEL_PATH.exists():
            self.model = json.loads(MODEL_PATH.read_text(encoding="utf-8"))
            logger.info("Loaded ML model from %s", MODEL_PATH)
            return
        logger.warning("ML model missing, training from dataset...")
        self.train(DATASET_PATH, MODEL_PATH)

    def _tokens(self, text: str) -> list[str]:
        return TOKEN_RE.findall(text.lower())

    def train(self, dataset_path: Path, model_path: Path) -> None:
        phish_counts: Counter[str] = Counter()
        safe_counts: Counter[str] = Counter()
        phish_docs = safe_docs = 0

        with dataset_path.open("r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                toks = self._tokens(row["text"])
                if int(row["label"]) == 1:
                    phish_docs += 1
                    phish_counts.update(toks)
                else:
                    safe_docs += 1
                    safe_counts.update(toks)

        vocab = sorted(set(phish_counts) | set(safe_counts))
        model = {
            "phish_docs": phish_docs,
            "safe_docs": safe_docs,
            "phish_total_tokens": sum(phish_counts.values()),
            "safe_total_tokens": sum(safe_counts.values()),
            "vocab_size": len(vocab),
            "phish_counts": dict(phish_counts),
            "safe_counts": dict(safe_counts),
        }

        model_path.parent.mkdir(parents=True, exist_ok=True)
        model_path.write_text(json.dumps(model, ensure_ascii=False), encoding="utf-8")
        self.model = model
        logger.info("Trained and saved ML model to %s", model_path)

    def predict(self, text: str) -> dict:
        if not self.model:
            return {"risk_score": 0, "is_phishing": False, "confidence": 0.0, "model": self.model_name}

        ph_docs = self.model["phish_docs"]
        sf_docs = self.model["safe_docs"]
        total_docs = max(1, ph_docs + sf_docs)

        log_phish = math.log(ph_docs / total_docs)
        log_safe = math.log(sf_docs / total_docs)

        ph_total = max(1, self.model["phish_total_tokens"])
        sf_total = max(1, self.model["safe_total_tokens"])
        vocab_size = max(1, self.model["vocab_size"])
        ph_counts = self.model["phish_counts"]
        sf_counts = self.model["safe_counts"]

        for tok in self._tokens(text):
            p_tok_ph = (ph_counts.get(tok, 0) + 1) / (ph_total + vocab_size)
            p_tok_sf = (sf_counts.get(tok, 0) + 1) / (sf_total + vocab_size)
            log_phish += math.log(p_tok_ph)
            log_safe += math.log(p_tok_sf)

        odds = math.exp(min(60, max(-60, log_phish - log_safe)))
        prob = odds / (1 + odds)
        risk = int(round(prob * 100))
        return {
            "risk_score": risk,
            "is_phishing": prob >= 0.5,
            "confidence": prob,
            "model": self.model_name,
        }

    def get_info(self) -> dict:
        return {
            "model": self.model_name,
            "model_path": str(MODEL_PATH),
            "dataset_path": str(DATASET_PATH),
            "dataset_exists": DATASET_PATH.exists(),
            "model_exists": MODEL_PATH.exists(),
        }
