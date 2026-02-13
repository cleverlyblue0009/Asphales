"""Pure-Python TF-IDF + Logistic Regression phishing classifier."""

from __future__ import annotations

import csv
import json
import math
import random
import re
from collections import Counter, defaultdict
from pathlib import Path

from utils.logger import setup_logger

logger = setup_logger("ml_classifier")

BASE_DIR = Path(__file__).resolve().parents[1]
# Updated to use the real training data from markdown file
DATASET_PATH = BASE_DIR / "data" / "phishing_multilingual_from_md.csv"
MODEL_PATH = BASE_DIR / "models" / "phishing_tfidf_logreg_model.json"
TOKEN_RE = re.compile(r"\w+", re.UNICODE)


class MLPhishingClassifier:
    """TF-IDF + logistic regression implemented without external ML libs."""

    def __init__(self):
        self.model_name = "tfidf-logistic-regression"
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

    def _build_vocab_and_idf(self, docs_tokens: list[list[str]], max_features: int = 9000) -> tuple[dict[str, int], dict[int, float]]:
        df = Counter()
        tf_global = Counter()
        for toks in docs_tokens:
            tf_global.update(toks)
            df.update(set(toks))

        top_terms = [term for term, _ in tf_global.most_common(max_features)]
        vocab = {t: i for i, t in enumerate(top_terms)}

        n_docs = len(docs_tokens)
        idf: dict[int, float] = {}
        for term, idx in vocab.items():
            idf[idx] = math.log((1 + n_docs) / (1 + df[term])) + 1.0
        return vocab, idf

    def _vectorize(self, toks: list[str], vocab: dict[str, int], idf: dict[int, float]) -> dict[int, float]:
        counts = Counter(t for t in toks if t in vocab)
        if not counts:
            return {}
        total = sum(counts.values())
        vec = {}
        for term, c in counts.items():
            idx = vocab[term]
            tf = c / total
            vec[idx] = tf * idf[idx]
        norm = math.sqrt(sum(v * v for v in vec.values()))
        if norm > 0:
            for k in list(vec.keys()):
                vec[k] /= norm
        return vec

    def train(self, dataset_path: Path, model_path: Path) -> None:
        texts: list[str] = []
        labels: list[int] = []
        docs_tokens: list[list[str]] = []

        with dataset_path.open("r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                text = row["text"]
                label = int(row["label"])
                toks = self._tokens(text)
                texts.append(text)
                labels.append(label)
                docs_tokens.append(toks)

        vocab, idf = self._build_vocab_and_idf(docs_tokens)
        vectors = [self._vectorize(toks, vocab, idf) for toks in docs_tokens]

        weights = defaultdict(float)
        bias = 0.0
        lr = 0.35
        reg = 1e-5
        epochs = 18

        idxs = list(range(len(vectors)))
        random.seed(42)

        for _ in range(epochs):
            random.shuffle(idxs)
            for i in idxs:
                x = vectors[i]
                y = labels[i]
                z = bias + sum(weights[j] * v for j, v in x.items())
                p = 1.0 / (1.0 + math.exp(-max(-30, min(30, z))))
                err = p - y

                for j, v in x.items():
                    weights[j] -= lr * (err * v + reg * weights[j])
                bias -= lr * err

            lr *= 0.93

        model = {
            "model": self.model_name,
            "vocab": vocab,
            "idf": {str(k): v for k, v in idf.items()},
            "weights": {str(k): w for k, w in weights.items()},
            "bias": bias,
        }

        model_path.parent.mkdir(parents=True, exist_ok=True)
        model_path.write_text(json.dumps(model, ensure_ascii=False), encoding="utf-8")
        self.model = model
        logger.info("Trained and saved ML model to %s", model_path)

    def predict(self, text: str) -> dict:
        if not self.model:
            return {"risk_score": 0, "is_phishing": False, "confidence": 0.0, "model": self.model_name}

        vocab = self.model["vocab"]
        idf = {int(k): float(v) for k, v in self.model["idf"].items()}
        weights = {int(k): float(v) for k, v in self.model["weights"].items()}
        bias = float(self.model["bias"])

        x = self._vectorize(self._tokens(text), vocab, idf)
        z = bias + sum(weights.get(i, 0.0) * v for i, v in x.items())
        prob = 1.0 / (1.0 + math.exp(-max(-30, min(30, z))))
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
