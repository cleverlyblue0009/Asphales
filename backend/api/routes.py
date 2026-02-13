"""API route definitions for SurakshaAI Shield."""

import re
import time
from typing import Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from context_engine import calculate_contextual_risk, extract_links
from services.classifier import HybridClassifier
from context_engine import calculate_contextual_risk, extract_links
from explanation_engine import ExplanationEngine
from utils.logger import setup_logger

logger = setup_logger("api")

router = APIRouter()
classifier: Optional[HybridClassifier] = None
_start_time: float = time.time()
explainer = ExplanationEngine()

SCAM_HINT_RE = re.compile(
    r"(otp|password|pin|cvv|kyc|verify|verification|account\s*(blocked|suspend|freeze)|"
    r"click\s*here|update\s*now|urgent|immediately|bank|sbi|hdfc|icici|rbi|"
    r"तुरंत|ओटीपी|पासवर्ड|உடனே|ஒடிபி|কেওয়াইসি|এখনই)",
    re.IGNORECASE,
)


def set_classifier(c: HybridClassifier) -> None:
    global classifier
    classifier = c


class AnalyzeRequest(BaseModel):
    text: str = Field(min_length=1, max_length=5000)


class BatchAnalyzeRequest(BaseModel):
    texts: list[str] = Field(min_length=1, max_length=50)


@router.get("/")
async def health_check():
    uptime = time.time() - _start_time
    return {
        "status": "ok",
        "service": "SurakshaAI Shield",
        "version": "1.0.0",
        "uptime_seconds": round(uptime, 1),
        "genai_available": classifier.genai.is_available() if classifier else False,
    }


@router.post("/analyze")
async def analyze(request: AnalyzeRequest):
    if classifier is None:
        raise HTTPException(status_code=503, detail="Classifier not initialized")
    result = await classifier.classify(request.text)
    return result.to_dict()


@router.post("/batch-analyze")
async def batch_analyze(request: BatchAnalyzeRequest):
    if classifier is None:
        raise HTTPException(status_code=503, detail="Classifier not initialized")
    results = await classifier.batch_classify(request.texts)
    return {"results": [r.to_dict() for r in results], "count": len(results)}


@router.get("/stats")
async def stats():
    if classifier is None:
        raise HTTPException(status_code=503, detail="Classifier not initialized")
    return classifier.get_stats()


@router.get("/patterns")
async def patterns():
    """Deprecated route retained for compatibility."""
    return {
        "deprecated": True,
        "message": "Pattern matching removed. Use /stats for ML model information.",
        "total_patterns": 0,
    }


def _deterministic_explanation(risk_level: str, signals: list[str], ml_score: float) -> dict:
    primary_reason = (
        "Bank impersonation with urgency and suspicious credential request."
        if any("Impersonation" in s for s in signals)
        else (signals[0] if signals else "No strong phishing indicator detected.")
    )

    tactics = []
    if any("Urgency" in s for s in signals):
        tactics.append("Urgency")
    if any("Impersonation" in s for s in signals):
        tactics.append("Authority")
    if any("credential" in s.lower() for s in signals):
        tactics.append("Fear")

    technical = []
    if any("URL" in s for s in signals):
        technical.append("Suspicious URL")
    if any("credential" in s.lower() for s in signals):
        technical.append("Credential Harvesting Pattern")

    confidence = "High" if ml_score >= 0.8 else "Medium" if ml_score >= 0.45 else "Low"

    return {
        "risk_level": risk_level,
        "primary_reason": primary_reason,
        "psychological_tactics": tactics,
        "technical_indicators": technical,
        "confidence": confidence,
    }


@router.post("/analyze_text")
async def analyze_text(request: AnalyzeRequest):
    if classifier is None:
        raise HTTPException(status_code=503, detail="Classifier not initialized")

    text = request.text
    links = extract_links(text)

    doc_ml = classifier.ml.predict(text)
    doc_prob = float(doc_ml.get("confidence", 0.0))

    # Line-level evidence extraction to avoid noisy whole-page false positives.
    lines = [ln.strip() for ln in re.split(r"\n+", text) if len(ln.strip()) >= 20]
    line_hits: list[dict] = []

    for line in lines[:120]:
        if not (SCAM_HINT_RE.search(line) or "http://" in line.lower() or "https://" in line.lower()):
            continue

        prob = float(classifier.ml.predict(line).get("confidence", 0.0))
        if prob < 0.50 and not SCAM_HINT_RE.search(line):
            continue

        line_hits.append(
            {
                "phrase": line[:260],
                "risk_score": round(prob, 4),
                "reason": "Suspicious sentence-level phishing pattern",
            }
        )

    line_hits = sorted(line_hits, key=lambda x: x["risk_score"], reverse=True)
    top_hits = line_hits[:6]

    detected_features = []
    if any(re.search(r"(otp|password|pin|cvv|kyc)", hit["phrase"], re.IGNORECASE) for hit in top_hits):
        detected_features.append("Credential request")
    if any(re.search(r"(bank|sbi|hdfc|icici|rbi)", hit["phrase"], re.IGNORECASE) for hit in top_hits):
        detected_features.append("Impersonation context")
    if any(re.search(r"(urgent|immediately|24 hours|final warning|तुरंत|எச்சரிக்கை|এখনই)", hit["phrase"], re.IGNORECASE) for hit in top_hits):
        detected_features.append("Urgency phrase")

    evidence_prob = max((h["risk_score"] for h in top_hits), default=0.0)
    base_prob = max(doc_prob, evidence_prob)

    ctx = calculate_contextual_risk(
        text=text,
        detected_features=detected_features,
        links=links,
        base_score=base_prob,
    )

    explanation = _deterministic_explanation(ctx["risk_level"], ctx["detected_signals"], ctx["risk_score"])

    return {
        "risk_score": ctx["risk_score"],
        "risk_level": ctx["risk_level"],
        "detected_signals": ctx["detected_signals"],
        "context_boost": ctx["context_boost"],
        "suspicious_segments": top_hits,
        "ml": {"risk_score": base_prob, "is_phishing": base_prob >= 0.5},
        "links": links,
        "genai_validation": {"enabled": False, "note": "GenAI validation disabled for precision/stability."},
        "structured_explanation": explanation,
    }
