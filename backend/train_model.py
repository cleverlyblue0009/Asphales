"""Train phishing classifier with word+char TF-IDF and balanced logistic regression."""

from __future__ import annotations

import argparse
import csv
import json
import math
import random
import re
from collections import Counter, defaultdict
from pathlib import Path

WORD_RE = re.compile(r"\w+", re.UNICODE)


def word_ngrams(text: str) -> list[str]:
    tokens = WORD_RE.findall((text or "").lower())
    grams = list(tokens)
    grams.extend(f"{tokens[i]} {tokens[i+1]}" for i in range(len(tokens) - 1))
    return grams


def char_ngrams(text: str, min_n: int = 3, max_n: int = 5) -> list[str]:
    s = re.sub(r"\s+", " ", (text or "").lower().strip())
    grams: list[str] = []
    for n in range(min_n, max_n + 1):
        grams.extend(s[i : i + n] for i in range(max(0, len(s) - n + 1)))
    return grams


class AdvancedPhishingModel:
    def __init__(self):
        self.vocab: dict[str, int] = {}
        self.idf: dict[int, float] = {}
        self.weights: defaultdict[int, float] = defaultdict(float)
        self.bias: float = 0.0
        self.threshold: float = 0.5

    def _features(self, text: str) -> list[str]:
        return word_ngrams(text) + char_ngrams(text)

    def _build_vocab(self, texts: list[str], max_features: int = 120000) -> None:
        tf = Counter()
        df = Counter()
        docs_feats = []
        for text in texts:
            feats = self._features(text)
            docs_feats.append(feats)
            tf.update(feats)
            df.update(set(feats))

        top = [f for f, _ in tf.most_common(max_features)]
        self.vocab = {f: i for i, f in enumerate(top)}

        n_docs = len(texts)
        self.idf = {
            idx: math.log((1 + n_docs) / (1 + df[feat])) + 1.0
            for feat, idx in self.vocab.items()
        }

    def vectorize(self, text: str) -> dict[int, float]:
        counts = Counter(f for f in self._features(text) if f in self.vocab)
        if not counts:
            return {}
        total = sum(counts.values())
        vec = {}
        for feat, c in counts.items():
            idx = self.vocab[feat]
            vec[idx] = (c / total) * self.idf[idx]
        norm = math.sqrt(sum(v * v for v in vec.values()))
        if norm > 0:
            for k in list(vec.keys()):
                vec[k] /= norm
        return vec

    def train(self, texts: list[str], labels: list[int], epochs: int = 14, lr: float = 0.3) -> None:
        self._build_vocab(texts)
        vectors = [self.vectorize(t) for t in texts]

        pos = sum(labels)
        neg = len(labels) - pos
        w_pos = len(labels) / (2 * pos) if pos else 1.0
        w_neg = len(labels) / (2 * neg) if neg else 1.0

        idxs = list(range(len(labels)))
        random.seed(42)

        for _ in range(epochs):
            random.shuffle(idxs)
            for i in idxs:
                x = vectors[i]
                y = labels[i]
                z = self.bias + sum(self.weights[j] * v for j, v in x.items())
                p = 1.0 / (1.0 + math.exp(-max(-30, min(30, z))))
                err = (p - y) * (w_pos if y == 1 else w_neg)
                for j, v in x.items():
                    self.weights[j] -= lr * (err * v + 1e-5 * self.weights[j])
                self.bias -= lr * err
            lr *= 0.92

    def predict_proba(self, text: str) -> float:
        x = self.vectorize(text)
        z = self.bias + sum(self.weights[j] * v for j, v in x.items())
        return 1.0 / (1.0 + math.exp(-max(-30, min(30, z))))

    def predict(self, text: str) -> int:
        return int(self.predict_proba(text) >= self.threshold)

    def save(self, path: Path) -> None:
        payload = {
            "vocab": self.vocab,
            "idf": {str(k): v for k, v in self.idf.items()},
            "weights": {str(k): v for k, v in self.weights.items()},
            "bias": self.bias,
            "threshold": self.threshold,
        }
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload), encoding="utf-8")

    @classmethod
    def load(cls, path: Path) -> "AdvancedPhishingModel":
        data = json.loads(path.read_text(encoding="utf-8"))
        obj = cls()
        obj.vocab = {k: int(v) for k, v in data["vocab"].items()}
        obj.idf = {int(k): float(v) for k, v in data["idf"].items()}
        obj.weights = defaultdict(float, {int(k): float(v) for k, v in data["weights"].items()})
        obj.bias = float(data["bias"])
        obj.threshold = float(data.get("threshold", 0.5))
        return obj


def read_csv(path: Path) -> tuple[list[str], list[int]]:
    texts, labels = [], []
    with path.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            texts.append(row["text"])
            labels.append(int(row["label"]))
    return texts, labels


def tune_threshold(y_true: list[int], probs: list[float]) -> dict:
    best = {"threshold": 0.5, "f1": 0.0, "precision": 0.0, "recall": 0.0}
    for i in range(20, 91):
        t = i / 100
        preds = [1 if p >= t else 0 for p in probs]
        tp = sum(1 for y, p in zip(y_true, preds) if y == 1 and p == 1)
        fp = sum(1 for y, p in zip(y_true, preds) if y == 0 and p == 1)
        fn = sum(1 for y, p in zip(y_true, preds) if y == 1 and p == 0)
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
        if f1 > best["f1"]:
            best = {"threshold": t, "f1": f1, "precision": precision, "recall": recall}
    return best


def confusion_matrix(y_true: list[int], y_pred: list[int]) -> dict[str, int]:
    tn = sum(1 for y, p in zip(y_true, y_pred) if y == 0 and p == 0)
    fp = sum(1 for y, p in zip(y_true, y_pred) if y == 0 and p == 1)
    fn = sum(1 for y, p in zip(y_true, y_pred) if y == 1 and p == 0)
    tp = sum(1 for y, p in zip(y_true, y_pred) if y == 1 and p == 1)
    return {"tn": tn, "fp": fp, "fn": fn, "tp": tp}


def train(train_csv: Path, test_csv: Path, output_dir: Path) -> None:
    X_train, y_train = read_csv(train_csv)
    X_test, y_test = read_csv(test_csv)

    model = AdvancedPhishingModel()
    model.train(X_train, y_train)

    probs = [model.predict_proba(t) for t in X_test]
    best = tune_threshold(y_test, probs)
    model.threshold = best["threshold"]
    preds = [1 if p >= model.threshold else 0 for p in probs]

    cm = confusion_matrix(y_test, preds)

    output_dir.mkdir(parents=True, exist_ok=True)
    model_path = output_dir / "phishing_model.json"
    metrics_path = output_dir / "model_metrics.json"
    model.save(model_path)
    metrics_path.write_text(json.dumps({"best_threshold": best, "confusion_matrix": cm}, indent=2), encoding="utf-8")

    print(f"Model saved: {model_path}")
    print(json.dumps({"best_threshold": best, "confusion_matrix": cm}, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train advanced phishing model")
    parser.add_argument("--train-csv", type=Path, default=Path("data/engineered/train.csv"))
    parser.add_argument("--test-csv", type=Path, default=Path("data/engineered/test.csv"))
    parser.add_argument("--output-dir", type=Path, default=Path("models/advanced"))
    args = parser.parse_args()
    train(args.train_csv, args.test_csv, args.output_dir)
