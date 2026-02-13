"""Train multilingual phishing ML model."""

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from services.ml_classifier import DATASET_PATH, MODEL_PATH, MLPhishingClassifier

if __name__ == "__main__":
    clf = MLPhishingClassifier()
    clf.train(Path(DATASET_PATH), Path(MODEL_PATH))
    print("Training complete")
