"""Phishing classifier combining ML scoring + GenAI explanation."""

import time
from typing import Optional

from models.risk_scorer import RiskResult, RiskScorer, ThreatDetail
from services.cache_manager import CacheManager
from services.genai_analyzer import GenAIAnalyzer
from services.ml_classifier import MLPhishingClassifier
from utils.logger import setup_logger
from utils.text_processor import text_hash, validate_length

logger = setup_logger("classifier")


class HybridClassifier:
    """ML-first classifier with optional GenAI reasoning."""

    def __init__(self):
        self.risk_scorer = RiskScorer()
        self.genai = GenAIAnalyzer()
        self.ml = MLPhishingClassifier()
        self.cache = CacheManager(max_size=1000, ttl=60)

        self.total_requests = 0
        self.total_time_ms = 0.0

        logger.info(
            "Classifier ready — ML model=%s, GenAI %s",
            self.ml.model_name,
            "enabled" if self.genai.is_available() else "disabled",
        )

    async def classify(self, text: str) -> RiskResult:
        self.total_requests += 1
        start = time.time()

        valid, _ = validate_length(text)
        if not valid:
            return RiskResult(
                overall_risk=0,
                severity="low",
                threats=[],
                method="error",
                processing_time_ms=0,
            )

        key = text_hash(text)
        cached = self.cache.get(key)
        if cached is not None:
            elapsed = (time.time() - start) * 1000
            cached.processing_time_ms = elapsed
            cached.cached = True
            self.total_time_ms += elapsed
            return cached

        ml_result = self.ml.predict(text)
        ml_score = ml_result["risk_score"]

        genai_score: Optional[int] = None
        threats: list[ThreatDetail] = []

        if self.genai.is_available() and (ml_score >= 35 or ml_score <= 20):
            genai_result = await self.genai.analyze(text)
            if genai_result is not None:
                genai_score = genai_result["risk_score"]
                explanation = genai_result.get("explanation_hinglish", "GenAI suspicious analysis")
                for tactic in genai_result.get("tactics", []):
                    threats.append(
                        ThreatDetail(
                            phrase=tactic,
                            risk=genai_score,
                            category="genai_detected",
                            explanation=explanation,
                        )
                    )

        final_score = ml_score if genai_score is None else int((ml_score * 0.6) + (genai_score * 0.4))
        severity = self.risk_scorer.get_severity(final_score)

        if not threats and final_score >= 55:
            threats.append(
                ThreatDetail(
                    phrase=text[:220],
                    risk=final_score,
                    category="ml_detected",
                    explanation="ML model ne is message ko phishing-like classify kiya hai based on multilingual scam patterns.",
                )
            )

        result = RiskResult(
            overall_risk=final_score,
            severity=severity,
            threats=threats,
            method="ml+genai" if genai_score is not None else "ml",
            ml_score=ml_score,
            genai_score=genai_score,
            processing_time_ms=(time.time() - start) * 1000,
        )

        self.total_time_ms += result.processing_time_ms
        self.cache.set(key, result)
        return result

    async def batch_classify(self, texts: list[str]) -> list[RiskResult]:
        return [await self.classify(text) for text in texts]

    def get_stats(self) -> dict:
        avg_time = self.total_time_ms / self.total_requests if self.total_requests else 0.0
        return {
            "total_requests": self.total_requests,
            "avg_response_time_ms": round(avg_time, 1),
            "genai_available": self.genai.is_available(),
            "ml": self.ml.get_info(),
            "cache": self.cache.stats(),
        }
