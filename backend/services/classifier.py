"""Hybrid phishing classifier combining pattern matching and GenAI analysis."""

import os
import time
from typing import Optional

from models.pattern_matcher import PatternMatcher
from models.risk_scorer import RiskResult, RiskScorer, ThreatDetail
from services.cache_manager import CacheManager
from services.genai_analyzer import GenAIAnalyzer
from utils.logger import setup_logger
from utils.text_processor import preprocess, text_hash, validate_length

logger = setup_logger("classifier")


class HybridClassifier:
    """Two-stage phishing classifier.

    Stage 1 — fast pattern matching (<100 ms).
    Stage 2 — GenAI analysis (1-3 s), triggered conditionally.
    """

    def __init__(self):
        self.pattern_matcher = PatternMatcher()
        self.risk_scorer = RiskScorer()
        self.genai = GenAIAnalyzer()
        ttl = int(os.getenv("CACHE_TTL", "60"))
        max_size = int(os.getenv("MAX_CACHE_SIZE", "1000"))
        self.cache = CacheManager(max_size=max_size, ttl=ttl)

        # Stats
        self.total_requests = 0
        self.total_time_ms = 0.0

        logger.info(
            "HybridClassifier ready — %d patterns loaded, GenAI %s",
            self.pattern_matcher.get_pattern_count(),
            "enabled" if self.genai.is_available() else "disabled",
        )

    async def classify(self, text: str) -> RiskResult:
        """Run the full classification pipeline on a single message."""
        self.total_requests += 1
        start = time.time()

        # Validate input
        valid, err = validate_length(text)
        if not valid:
            return RiskResult(
                overall_risk=0,
                severity="low",
                threats=[],
                method="error",
                processing_time_ms=0,
            )

        # Check cache
        key = text_hash(text)
        cached = self.cache.get(key)
        if cached is not None:
            elapsed = (time.time() - start) * 1000
            cached.processing_time_ms = elapsed
            cached.cached = True
            self.total_time_ms += elapsed
            logger.info("Returning cached result for text hash %s", key[:16])
            return cached

        processed = preprocess(text)

        # Stage 1: Pattern matching
        matches = self.pattern_matcher.match(processed)
        pattern_score = self.pattern_matcher.calculate_score(matches)
        logger.info(
            "Stage 1 — pattern_score=%d, matches=%d",
            pattern_score,
            len(matches),
        )

        # Stage 2: GenAI (conditional)
        genai_score: Optional[int] = None
        genai_threats: list[ThreatDetail] = []

        if self._should_use_genai(pattern_score):
            genai_result = await self.genai.analyze(text)
            if genai_result is not None:
                genai_score = genai_result["risk_score"]
                # Build extra threats from GenAI tactics
                for tactic in genai_result.get("tactics", []):
                    genai_threats.append(
                        ThreatDetail(
                            phrase=tactic,
                            risk=genai_score,
                            category="genai_detected",
                            explanation=genai_result.get(
                                "explanation_hinglish",
                                "GenAI ne yeh suspicious pattern detect kiya.",
                            ),
                        )
                    )
                logger.info("Stage 2 — genai_score=%d", genai_score)

        # Combine
        result = self.risk_scorer.score(
            pattern_score=pattern_score,
            matches=matches,
            genai_score=genai_score,
        )

        # Append GenAI-only threats
        result.threats.extend(genai_threats)

        elapsed = (time.time() - start) * 1000
        result.processing_time_ms = elapsed
        self.total_time_ms += elapsed

        # Cache result
        self.cache.set(key, result)

        logger.info(
            "Classification complete — overall_risk=%d, severity=%s, method=%s, time=%.1fms",
            result.overall_risk,
            result.severity,
            result.method,
            elapsed,
        )
        return result

    async def batch_classify(self, texts: list[str]) -> list[RiskResult]:
        """Classify multiple messages sequentially."""
        results = []
        for text in texts:
            results.append(await self.classify(text))
        return results

    def _should_use_genai(self, pattern_score: int) -> bool:
        """Decide whether GenAI analysis is needed based on pattern score."""
        if not self.genai.is_available():
            return False
        # Uncertain zone or high risk needing explanation
        return pattern_score >= 30

    def get_stats(self) -> dict:
        """Return classifier statistics."""
        avg_time = (
            self.total_time_ms / self.total_requests
            if self.total_requests > 0
            else 0.0
        )
        return {
            "total_requests": self.total_requests,
            "avg_response_time_ms": round(avg_time, 1),
            "pattern_count": self.pattern_matcher.get_pattern_count(),
            "genai_available": self.genai.is_available(),
            "cache": self.cache.stats(),
        }
