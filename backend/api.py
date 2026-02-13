"""Standalone FastAPI service for deterministic ML + context phishing analysis."""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from context_engine import calculate_contextual_risk, extract_links
from train_model import AdvancedPhishingModel

MODEL_PATH = Path("models/advanced/phishing_model.json")


class AnalyzeRequest(BaseModel):
    text: str = Field(min_length=1, max_length=5000)


class InferenceEngine:
    def __init__(self, model_path: Path):
        if not model_path.exists():
            raise FileNotFoundError(f"Model not found at {model_path}")
        self.model = AdvancedPhishingModel.load(model_path)

    def predict(self, text: str) -> dict:
        prob = float(self.model.predict_proba(text))
        return {
            "risk_score": prob,
            "is_phishing": prob >= self.model.threshold,
            "threshold": self.model.threshold,
        }


app = FastAPI(title="SurakshaAI Advanced Detector", version="2.1.0")
engine: InferenceEngine | None = None


@app.on_event("startup")
def startup() -> None:
    global engine
    engine = InferenceEngine(MODEL_PATH)


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "model_loaded": engine is not None}


@app.post("/analyze_text")
def analyze_text(request: AnalyzeRequest) -> dict:
    if engine is None:
        raise HTTPException(status_code=503, detail="Model not initialized")

    text = request.text
    links = extract_links(text)
    ml = engine.predict(text)
    ctx = calculate_contextual_risk(text=text, detected_features=[], links=links, base_score=ml["risk_score"])

    return {
        "risk_score": ctx["risk_score"],
        "risk_level": ctx["risk_level"],
        "detected_signals": ctx["detected_signals"],
        "context_boost": ctx["context_boost"],
        "ml": ml,
        "links": links,
        "genai_validation": {"enabled": False},
        "structured_explanation": {
            "risk_level": ctx["risk_level"],
            "primary_reason": ", ".join(ctx["detected_signals"][:2]) or "No strong phishing signal detected.",
            "psychological_tactics": ["Urgency"] if any("Urgency" in s for s in ctx["detected_signals"]) else [],
            "technical_indicators": [s for s in ctx["detected_signals"] if "URL" in s],
            "confidence": "High" if ctx["risk_score"] >= 0.8 else "Medium",
        },
    }
