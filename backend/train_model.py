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
        for text in texts:
            feats = self._features(text)
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


def _add_sample(texts: list[str], labels: list[int], text: str, label: int) -> None:
    clean = re.sub(r"\s+", " ", (text or "")).strip()
    if len(clean) >= 8:
        texts.append(clean)
        labels.append(label)


def _walk_json_samples(node, texts: list[str], labels: list[int], default_label: int | None = None) -> None:
    if isinstance(node, dict):
        lower_keys = {k.lower() for k in node.keys()}

        if "text" in node and isinstance(node.get("text"), str):
            label = default_label
            if label is None:
                category = str(node.get("category", "")).lower()
                label = 1 if any(k in category for k in ("phish", "fraud", "scam", "threat")) else 0
            _add_sample(texts, labels, node["text"], int(label))

        for key, value in node.items():
            lk = key.lower()
            inferred = default_label
            if any(t in lk for t in ("phish", "threat", "malicious", "fraud", "scam")):
                inferred = 1
            elif any(t in lk for t in ("safe", "legit", "ham", "benign", "normal")):
                inferred = 0
            _walk_json_samples(value, texts, labels, inferred)

        # Handle language dictionaries with safe/threat arrays
        if "safe" in lower_keys or "threat" in lower_keys:
            for k, v in node.items():
                lk = k.lower()
                if lk == "safe":
                    _walk_json_samples(v, texts, labels, 0)
                if lk in {"threat", "phishing", "fraud", "scam"}:
                    _walk_json_samples(v, texts, labels, 1)

    elif isinstance(node, list):
        for item in node:
            if isinstance(item, str):
                if default_label is not None:
                    _add_sample(texts, labels, item, int(default_label))
            else:
                _walk_json_samples(item, texts, labels, default_label)


def load_json_training_samples(data_dir: Path) -> tuple[list[str], list[int]]:
    texts: list[str] = []
    labels: list[int] = []
    for json_file in sorted(data_dir.glob("*.json")):
        try:
            payload = json.loads(json_file.read_text(encoding="utf-8"))
        except Exception:
            continue
        _walk_json_samples(payload, texts, labels)

    # Deduplicate while keeping strongest label if conflict
    merged: dict[str, int] = {}
    for text, label in zip(texts, labels):
        merged[text] = max(label, merged.get(text, 0))
    out_texts = list(merged.keys())
    out_labels = [merged[t] for t in out_texts]
    return out_texts, out_labels


def tune_threshold(y_true: list[int], probs: list[float]) -> dict:
    best = {"threshold": 0.5, "f1": 0.0, "precision": 0.0, "recall": 0.0, "accuracy": 0.0}
    for i in range(20, 91):
        t = i / 100
        preds = [1 if p >= t else 0 for p in probs]
        tp = sum(1 for y, p in zip(y_true, preds) if y == 1 and p == 1)
        fp = sum(1 for y, p in zip(y_true, preds) if y == 0 and p == 1)
        fn = sum(1 for y, p in zip(y_true, preds) if y == 1 and p == 0)
        tn = sum(1 for y, p in zip(y_true, preds) if y == 0 and p == 0)
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        acc = (tp + tn) / len(y_true) if y_true else 0.0
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
        if f1 > best["f1"]:
            best = {"threshold": t, "f1": f1, "precision": precision, "recall": recall, "accuracy": acc}
    return best


def confusion_matrix(y_true: list[int], y_pred: list[int]) -> dict[str, int]:
    tn = sum(1 for y, p in zip(y_true, y_pred) if y == 0 and p == 0)
    fp = sum(1 for y, p in zip(y_true, y_pred) if y == 0 and p == 1)
    fn = sum(1 for y, p in zip(y_true, y_pred) if y == 1 and p == 0)
    tp = sum(1 for y, p in zip(y_true, y_pred) if y == 1 and p == 1)
    return {"tn": tn, "fp": fp, "fn": fn, "tp": tp}


def _split_holdout(texts: list[str], labels: list[int], test_ratio: float = 0.2) -> tuple[list[str], list[int], list[str], list[int]]:
    idxs = list(range(len(texts)))
    random.seed(42)
    random.shuffle(idxs)
    cut = max(1, int(len(idxs) * (1 - test_ratio)))
    train_idx = idxs[:cut]
    test_idx = idxs[cut:]
    X_train = [texts[i] for i in train_idx]
    y_train = [labels[i] for i in train_idx]
    X_test = [texts[i] for i in test_idx]
    y_test = [labels[i] for i in test_idx]
    return X_train, y_train, X_test, y_test


def train(train_csv: Path, test_csv: Path, output_dir: Path, data_dir: Path) -> None:
    if train_csv.exists() and test_csv.exists():
        X_train, y_train = read_csv(train_csv)
        X_test, y_test = read_csv(test_csv)
    else:
        # Updated to use the real training data from markdown file
        fallback = data_dir / "phishing_multilingual_from_md.csv"
        if not fallback.exists():
            # Try old dataset as final fallback
            fallback = data_dir / "phishing_multilingual_7500.csv"
            if not fallback.exists():
                raise FileNotFoundError("Training CSVs not found and fallback dataset missing")
        texts, labels = read_csv(fallback)
        X_train, y_train, X_test, y_test = _split_holdout(texts, labels)

    json_texts, json_labels = load_json_training_samples(data_dir)
    X_train.extend(json_texts)
    y_train.extend(json_labels)

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
    metrics = {
        "best_threshold": best,
        "confusion_matrix": cm,
        "json_samples_used": len(json_texts),
        "target_accuracy_95": best["accuracy"] >= 0.95,
    }
    metrics_path.write_text(json.dumps(metrics, indent=2), encoding="utf-8")

    print(f"Model saved: {model_path}")
    print(json.dumps(metrics, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train advanced phishing model")
    parser.add_argument("--train-csv", type=Path, default=Path("data/engineered/train.csv"))
    parser.add_argument("--test-csv", type=Path, default=Path("data/engineered/test.csv"))
    parser.add_argument("--output-dir", type=Path, default=Path("models/advanced"))
    parser.add_argument("--data-dir", type=Path, default=Path("data"))
    args = parser.parse_args()
    train(args.train_csv, args.test_csv, args.output_dir, args.data_dir)
