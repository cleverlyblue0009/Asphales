"""Standalone FastAPI service for deterministic ML + context phishing analysis."""

from __future__ import annotations

import re
from pathlib import Path

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from context_engine import calculate_contextual_risk, extract_links
from train_model import AdvancedPhishingModel

MODEL_PATH = Path("models/advanced/phishing_model.json")
SENTENCE_RE = re.compile(r"[^.!?\n]{12,}[.!?]?", re.UNICODE)


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


def _segments(text: str) -> list[str]:
    found = [s.strip() for s in SENTENCE_RE.findall(text or "") if s.strip()]
    return found or [text.strip()]


def _score_segments(text: str, base_score: float, model: AdvancedPhishingModel) -> list[dict]:
    sentences = _segments(text)
    if not sentences:
        return []

    scored: list[dict] = []
    for idx, sentence in enumerate(sentences):
        prev_txt = sentences[idx - 1] if idx > 0 else ""
        next_txt = sentences[idx + 1] if idx + 1 < len(sentences) else ""
        context_window = " ".join([prev_txt, sentence, next_txt]).strip()
        local_score = float(model.predict_proba(context_window))

        risk_score = min(1.0, (local_score * 0.75) + (base_score * 0.25))
        if risk_score >= 0.55:
            reason = "Likely phishing pattern in context window"
            lw = context_window.lower()
            if "otp" in lw or "password" in lw or "pin" in lw or "cvv" in lw:
                reason = "Credential harvesting intent"
            elif "http://" in lw or "https://" in lw:
                reason = "Suspicious action request with URL"
            elif "urgent" in lw or "immediately" in lw or "तुरंत" in lw:
                reason = "Urgency pressure tactic"

            scored.append(
                {
                    "phrase": sentence[:220],
                    "risk_score": round(risk_score, 4),
                    "reason": reason,
                }
            )

    return sorted(scored, key=lambda x: x["risk_score"], reverse=True)[:6]


app = FastAPI(title="SurakshaAI Advanced Detector", version="2.2.0")
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
    suspicious_segments = _score_segments(text=text, base_score=ctx["risk_score"], model=engine.model)

    level = ctx["risk_level"]
    confidence = "High" if ctx["risk_score"] >= 0.82 else "Medium" if ctx["risk_score"] >= 0.45 else "Low"
    explanation = "Context looks normal; no coordinated phishing cues detected."
    if suspicious_segments:
        explanation = "; ".join(seg["reason"] for seg in suspicious_segments[:2])

    return {
        "risk_score": ctx["risk_score"],
        "risk_level": level,
        "detected_signals": ctx["detected_signals"],
        "context_boost": ctx["context_boost"],
        "risk_band": level,
        "ml": ml,
        "links": links,
        "harmful_links": ctx.get("suspicious_links", []),
        "suspicious_segments": suspicious_segments,
        "genai_validation": {"enabled": False},
        "structured_explanation": {
            "risk_level": level,
            "primary_reason": explanation,
            "psychological_tactics": [s for s in ctx["detected_signals"] if "Urgency" in s or "pressure" in s.lower()],
            "technical_indicators": [s for s in ctx["detected_signals"] if "URL" in s or "credential" in s.lower()],
            "confidence": confidence,
        },
    }
