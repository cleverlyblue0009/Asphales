"""API route definitions for SurakshaAI Shield."""

import re
import time
from typing import Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from context_engine import calculate_contextual_risk, extract_links
from services.classifier import HybridClassifier
from explanation_engine import ExplanationEngine
from utils.logger import setup_logger
from utils.language_detector import get_language_info, get_primary_language
from utils.bilingual_explainer import get_bilingual_explanation, determine_reason_type

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




def _fallback_romanized_reason(reason_type: str) -> str:
    """Fallback romanized explanation when GenAI output is unavailable."""
    mapping = {
        "bank_impersonation": "Yeh message bank ya authority ban kar aapka private data maang raha hai.",
        "urgency_tactic": "Message turant action ka pressure create karta hai, jo phishing ka common pattern hai.",
        "credential_request": "Isme OTP/password/PIN jaisi sensitive details maangi ja rahi hain.",
        "suspicious_link": "Message me suspicious link hai jo fake website par le ja sakta hai.",
        "reward_scam": "Fake inaam ka lalach dekar personal data ya paisa lene ki koshish ho rahi hai.",
        "account_threat": "Account block/suspend ka dar dikhakar aapse jaldi decision liya ja raha hai.",
        "safe": "Koi strong phishing signal detect nahi hua, phir bhi link verify karke hi click karein.",
    }
    return mapping.get(reason_type, mapping["safe"])

def _enhanced_explanation(
    risk_level: str,
    signals: list[str],
    ml_score: float,
    language_info: dict,
    has_suspicious_links: bool,
    genai_reason: str = ""
) -> dict:
    """
    Generate enhanced bilingual explanation with better signal detection.
    """
    primary_language = language_info.get("primary_language", "English")

    # Determine tactics based on signals
    tactics = []
    if any("urgency" in s.lower() or "तुरंत" in s.lower() for s in signals):
        tactics.append("Urgency")
    if any("impersonation" in s.lower() or "brand" in s.lower() for s in signals):
        tactics.append("Authority")
    if any("credential" in s.lower() for s in signals):
        tactics.append("Fear")
    if any("reward" in s.lower() or "prize" in s.lower() or "इनाम" in s.lower() for s in signals):
        tactics.append("Greed")

    # Determine technical indicators
    technical = []
    if has_suspicious_links or any("url" in s.lower() or "link" in s.lower() for s in signals):
        technical.append("Suspicious URL")
    if any("credential" in s.lower() or "harvesting" in s.lower() for s in signals):
        technical.append("Credential Harvesting Pattern")
    if any("misspell" in s.lower() or "domain" in s.lower() for s in signals):
        technical.append("Misspelled Domain")

    # Determine reason type
    reason_type = determine_reason_type(signals, has_suspicious_links)

    # Get bilingual explanation
    bilingual = get_bilingual_explanation(primary_language, reason_type, tactics, technical)
    romanized_reason = genai_reason.strip() or _fallback_romanized_reason(reason_type)

    # Determine confidence
    confidence = "High" if ml_score >= 0.75 else "Medium" if ml_score >= 0.45 else "Low"

    # Format for frontend
    return {
        "risk_level": risk_level,
        "primary_reason": bilingual["primary_reason"]["en"],
        "primary_reason_vernacular": bilingual["primary_reason"]["vernacular"],
        "risk_reason_romanized": romanized_reason,
        "detected_language": primary_language,
        "psychological_tactics": [t["en"] for t in bilingual["psychological_tactics"]],
        "psychological_tactics_vernacular": [t["vernacular"] for t in bilingual["psychological_tactics"]],
        "technical_indicators": [t["en"] for t in bilingual["technical_indicators"]],
        "technical_indicators_vernacular": [t["vernacular"] for t in bilingual["technical_indicators"]],
        "confidence": confidence,
    }


@router.post("/analyze_text")
async def analyze_text(request: AnalyzeRequest):
    if classifier is None:
        raise HTTPException(status_code=503, detail="Classifier not initialized")

    text = request.text

    # Detect language and check for benign content
    language_info = get_language_info(text)

    # Early exit for clearly benign content (educational/informational)
    if language_info.get("likely_benign", False):
        # Still check for links, but apply strong dampening
        pass

    links = extract_links(text)

    doc_ml = classifier.ml.predict(text)
    doc_prob = float(doc_ml.get("confidence", 0.0))

    # Line-level evidence extraction with improved filtering
    lines = [ln.strip() for ln in re.split(r"\n+", text) if len(ln.strip()) >= 20]
    line_hits: list[dict] = []

    for line in lines[:120]:
        # Skip if line doesn't have scam hints or URLs
        if not (SCAM_HINT_RE.search(line) or "http://" in line.lower() or "https://" in line.lower()):
            continue

        # Check if line has benign indicators
        line_lower = line.lower()
        benign_count = sum(1 for term in ["class", "exam", "homework", "assignment", "meeting",
                                          "project", "tournament", "match", "schedule", "format",
                                          "style", "vit", "college", "university", "student"]
                          if term in line_lower)

        # Skip lines with strong benign indicators unless they also have high threat signals
        if benign_count >= 2:
            # Check for strong threat keywords
            threat_count = sum(1 for term in ["otp", "password", "pin", "cvv", "bank", "verify",
                                              "urgent", "immediately", "block", "suspend"]
                              if term in line_lower)
            if threat_count < 2:
                continue

        prob = float(classifier.ml.predict(line).get("confidence", 0.0))

        # Increased threshold to reduce false positives
        if prob < 0.60 and not SCAM_HINT_RE.search(line):
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

    # Enhanced feature detection
    detected_features = []
    if any(re.search(r"(otp|password|pin|cvv|kyc)", hit["phrase"], re.IGNORECASE) for hit in top_hits):
        detected_features.append("Credential request")
    if any(re.search(r"(bank|sbi|hdfc|icici|rbi|paytm|phonepe|gpay)", hit["phrase"], re.IGNORECASE) for hit in top_hits):
        detected_features.append("Impersonation context")
    if any(re.search(r"(urgent|immediately|24 hours|final warning|तुरंत|உடனே|এখনই)", hit["phrase"], re.IGNORECASE) for hit in top_hits):
        detected_features.append("Urgency phrase")
    if any(re.search(r"(prize|reward|won|winner|लॉटरी|इनाम|பரிசு)", hit["phrase"], re.IGNORECASE) for hit in top_hits):
        detected_features.append("Reward scam")

    evidence_prob = max((h["risk_score"] for h in top_hits), default=0.0)
    base_prob = max(doc_prob, evidence_prob)

    # Apply language-based dampening for benign content
    if language_info.get("likely_benign", False):
        base_prob = max(0.0, base_prob - 0.25)

    ctx = calculate_contextual_risk(
        text=text,
        detected_features=detected_features,
        links=links,
        base_score=base_prob,
    )

    # Filter harmful links (only include suspicious ones)
    harmful_links = ctx.get("suspicious_links", [])

    genai_result = await classifier.genai.analyze(text) if classifier.genai.is_available() else None
    genai_reason = genai_result.get("explanation_hinglish", "") if genai_result else ""

    # Generate enhanced bilingual explanation
    explanation = _enhanced_explanation(
        ctx["risk_level"],
        ctx["detected_signals"],
        ctx["risk_score"],
        language_info,
        len(harmful_links) > 0,
        genai_reason
    )

    return {
        "risk_score": ctx["risk_score"],
        "risk_level": ctx["risk_level"],
        "detected_signals": ctx["detected_signals"],
        "context_boost": ctx["context_boost"],
        "suspicious_segments": top_hits,
        "ml": {"risk_score": base_prob, "is_phishing": base_prob >= 0.5},
        "links": links,
        "harmful_links": harmful_links,  # NEW: Added harmful_links field
        "language_info": language_info,  # NEW: Added language information
        "genai_validation": {
            "enabled": bool(genai_result),
            "note": "GenAI explanation generated." if genai_result else "GenAI unavailable, fallback vernacular explanation used.",
            "explanation_romanized": genai_reason,
        },
        "structured_explanation": explanation,
    }
