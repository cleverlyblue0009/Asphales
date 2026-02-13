"""API route definitions for SurakshaAI Shield."""

import time
from typing import Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from services.classifier import HybridClassifier
from utils.logger import setup_logger

logger = setup_logger("api")

router = APIRouter()

# Shared classifier instance — set by app.py on startup
classifier: Optional[HybridClassifier] = None
_start_time: float = time.time()


def set_classifier(c: HybridClassifier) -> None:
    """Inject the classifier instance from the application."""
    global classifier
    classifier = c


# ---------- Request / Response models ----------

class AnalyzeRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=5000)


class BatchAnalyzeRequest(BaseModel):
    texts: list[str] = Field(..., min_length=1, max_length=50)


# ---------- Routes ----------

@router.get("/")
async def health_check():
    """Health check and service metadata."""
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
    """Analyze a single message for phishing indicators."""
    if classifier is None:
        raise HTTPException(status_code=503, detail="Classifier not initialized")

    result = await classifier.classify(request.text)
    return result.to_dict()


@router.post("/batch-analyze")
async def batch_analyze(request: BatchAnalyzeRequest):
    """Analyze multiple messages."""
    if classifier is None:
        raise HTTPException(status_code=503, detail="Classifier not initialized")

    results = await classifier.batch_classify(request.texts)
    return {"results": [r.to_dict() for r in results], "count": len(results)}


@router.get("/stats")
async def stats():
    """Return API and classifier statistics."""
    if classifier is None:
        raise HTTPException(status_code=503, detail="Classifier not initialized")

    return classifier.get_stats()


@router.get("/patterns")
async def patterns():
    """Return loaded phishing patterns for debugging."""
    if classifier is None:
        raise HTTPException(status_code=503, detail="Classifier not initialized")

    pm = classifier.pattern_matcher
    by_category: dict[str, list[dict]] = {}
    for p in pm.patterns:
        cat = p["category"]
        by_category.setdefault(cat, []).append(p)

    return {
        "total_patterns": pm.get_pattern_count(),
        "categories": list(pm.categories.keys()),
        "patterns_by_category": by_category,
    }
