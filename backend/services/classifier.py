"""Phishing classifier combining ML scoring + OpenAI + Advanced Link Analysis."""

import time
from typing import Optional

from models.risk_scorer import RiskResult, RiskScorer, ThreatDetail
from services.cache_manager import CacheManager
from services.genai_analyzer import GenAIAnalyzer
from services.openai_analyzer import OpenAIPhishingAnalyzer
from services.advanced_link_analyzer import AdvancedLinkAnalyzer
from services.ml_classifier import MLPhishingClassifier
from utils.logger import setup_logger
from utils.text_processor import text_hash, validate_length

logger = setup_logger("classifier")


class HybridClassifier:
    """Advanced ML classifier with OpenAI analysis, link detection, and multi-layer risk assessment."""

    def __init__(self):
        self.risk_scorer = RiskScorer()
        self.genai = GenAIAnalyzer()  # Keep for backwards compatibility
        self.openai = OpenAIPhishingAnalyzer()  # New OpenAI integration
        self.link_analyzer = AdvancedLinkAnalyzer()  # Advanced link detection
        self.ml = MLPhishingClassifier()
        self.cache = CacheManager(max_size=1000, ttl=60)

        self.total_requests = 0
        self.total_time_ms = 0.0

        logger.info(
            "Classifier ready — ML model=%s, GenAI %s, OpenAI %s, Advanced Link Analysis enabled",
            self.ml.model_name,
            "enabled" if self.genai.is_available() else "disabled",
            "enabled" if self.openai.enabled else "disabled",
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

        # Advanced link analysis
        link_score, tactics, warning_signs = self.link_analyzer.analyze_text_for_scams(text)
        if link_score > 0:
            ml_score = max(ml_score, int(link_score * 100))
            for warning in warning_signs:
                line_threats.append(
                    ThreatDetail(
                        phrase=warning,
                        risk=int(link_score * 100),
                        category="link_analysis",
                        explanation=f"Advanced threat detection identified: {warning}",
                    )
                )

        openai_score: Optional[int] = None
        openai_explanation: Optional[str] = None
        openai_confidence: Optional[float] = None

        # Try OpenAI first, fallback to GenAI (Anthropic)
        if self.openai.enabled:
            try:
                openai_result = await self.openai.analyze(text)
                if openai_result is not None:
                    openai_score = int(openai_result["risk_score"])
                    openai_explanation = openai_result.get("explanation")
                    openai_confidence = openai_result.get("confidence", 0.5)
                    if openai_result.get("is_phishing"):
                        tactics_list = openai_result.get("tactics", [])
                        tactic_text = ", ".join(tactics_list[:4]) if tactics_list else "suspicious patterns detected"
                        line_threats.append(
                            ThreatDetail(
                                phrase=tactic_text,
                                risk=openai_score,
                                category="openai_detected",
                                explanation=openai_explanation or "OpenAI detected phishing indicators in this message.",
                            )
                        )
            except Exception as e:
                logger.warning(f"OpenAI analysis error: {e}")

        genai_score: Optional[int] = None
        genai_explanation: Optional[str] = None

        # Fallback to GenAI (Anthropic) if OpenAI unavailable
        if self.genai.is_available() and openai_score is None:
            try:
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
                                explanation=genai_explanation or "Phishing patterns detected.",
                            )
                        )
            except Exception as e:
                logger.warning(f"GenAI analysis error: {e}")

        # Determine final score using priority: OpenAI > GenAI > ML
        ai_score = openai_score if openai_score is not None else genai_score
        final_score = ml_score if ai_score is None else max(ml_score, int((ml_score * 0.6) + (ai_score * 0.4)))
        severity = self.risk_scorer.get_severity(final_score)

        if not line_threats and final_score >= 45:
            line_threats.append(
                ThreatDetail(
                    phrase=text[:220],
                    risk=final_score,
                    category="ml_detected",
                    explanation="Machine learning detected suspicious patterns. Verify before clicking links or sharing information.",
                )
            )

        # Build method string
        method_parts = ["ml"]
        if openai_score is not None:
            method_parts.append("openai")
        elif genai_score is not None:
            method_parts.append("genai")

        result = RiskResult(
            overall_risk=final_score,
            severity=severity,
            threats=line_threats[:8],
            method="+".join(method_parts),
            ml_score=ml_score,
            genai_score=genai_score,
            openai_score=openai_score,
            openai_explanation=openai_explanation,
            openai_confidence=openai_confidence,
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
