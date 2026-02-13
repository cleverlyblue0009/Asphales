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
    """ML-first classifier with line-level risk aggregation and optional GenAI reasoning."""

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

        ml_doc_result = self.ml.predict(text)
        ml_doc_score = ml_doc_result["risk_score"]

        line_threats, max_line_score = self._score_suspicious_lines(text)
        ml_score = max(ml_doc_score, max_line_score)

        genai_score: Optional[int] = None
        genai_explanation: Optional[str] = None

        # Final GenAI check (when available) to reduce false negatives.
        if self.genai.is_available():
            genai_result = await self.genai.analyze(text)
            if genai_result is not None:
                genai_score = int(genai_result["risk_score"])
                genai_explanation = genai_result.get("explanation_hinglish")
                if genai_result.get("is_phishing"):
                    tactic_text = ", ".join(genai_result.get("tactics", [])[:4]) or "contextual phishing indicators"
                    line_threats.append(
                        ThreatDetail(
                            phrase=tactic_text,
                            risk=genai_score,
                            category="genai_detected",
                            explanation=genai_explanation or "GenAI ne suspicious social-engineering pattern detect kiya.",
                        )
                    )

        final_score = ml_score if genai_score is None else max(ml_score, int((ml_score * 0.65) + (genai_score * 0.35)))
        severity = self.risk_scorer.get_severity(final_score)

        if not line_threats and final_score >= 45:
            line_threats.append(
                ThreatDetail(
                    phrase=text[:220],
                    risk=final_score,
                    category="ml_detected",
                    explanation="ML + contextual analysis ne message ko suspicious classify kiya. Link/OTP/KYC details verify kiye bina action mat lo.",
                )
            )

        result = RiskResult(
            overall_risk=final_score,
            severity=severity,
            threats=line_threats[:8],
            method="ml+genai" if genai_score is not None else "ml",
            ml_score=ml_score,
            genai_score=genai_score,
            processing_time_ms=(time.time() - start) * 1000,
        )

        self.total_time_ms += result.processing_time_ms
        self.cache.set(key, result)
        return result

    def _score_suspicious_lines(self, text: str) -> tuple[list[ThreatDetail], int]:
        lines = [ln.strip() for ln in text.splitlines() if len(ln.strip()) >= 20]
        threats: list[ThreatDetail] = []
        max_line = 0

        for line in lines:
            line_risk = self.ml.predict(line)["risk_score"]
            max_line = max(max_line, line_risk)
            if line_risk >= 52:
                threats.append(
                    ThreatDetail(
                        phrase=line[:220],
                        risk=line_risk,
                        category="ml_line_detected",
                        explanation="Is specific line mein phishing-like pattern hai (OTP/KYC/account urgency/credential bait).",
                    )
                )

        deduped: dict[str, ThreatDetail] = {}
        for t in threats:
            deduped[t.phrase] = t
        sorted_threats = sorted(deduped.values(), key=lambda x: x.risk, reverse=True)
        return sorted_threats, max_line

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
