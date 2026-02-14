"""Risk scoring and severity classification for phishing detection results."""

from typing import Any, Optional

SEVERITY_LEVELS = {
    "low": (0, 30),
    "medium": (30, 60),
    "high": (60, 85),
    "critical": (85, 101),
}

CATEGORY_EXPLANATIONS = {
    "credential_request": "Yeh message aapke password, OTP, ya login details maang raha hai. Koi bhi asli bank ya company aapke credentials nahi maangti.",
    "urgency": "Yeh message jaldi action lene ke liye pressure daal raha hai. Scammers urgency create karte hain taaki aap bina soche action le lo.",
    "impersonation": "Yeh message kisi bank, government, ya authority ka naam use kar raha hai. Verify karo ki yeh asli hai ya nahi.",
    "suspicious_links": "Is message mein suspicious link hai. Unknown links pe click mat karo, malware ya phishing site ho sakti hai.",
    "money_request": "Yeh message paise maang raha hai. Processing fee, registration fee, ya advance payment maangna ek common scam hai.",
    "fear_tactics": "Yeh message daraa raha hai - arrest, account block, legal action. Asli authorities aise threaten nahi karte.",
    "too_good_to_be_true": "Yeh message bahut accha offer de raha hai - lottery, prize, free gifts. Agar kuch bahut accha lagta hai toh shayad scam hai.",
    "personal_info": "Yeh message aapki personal information maang raha hai - Aadhar, PAN, bank details. Yeh information share mat karo.",
}


class ThreatDetail:
    """Describes a single detected threat with explanation."""

    def __init__(
        self,
        phrase: str,
        risk: int,
        category: str,
        explanation: str,
    ):
        self.phrase = phrase
        self.risk = risk
        self.category = category
        self.explanation = explanation

    def to_dict(self) -> dict:
        return {
            "phrase": self.phrase,
            "risk": self.risk,
            "category": self.category,
            "explanation": self.explanation,
        }


class RiskResult:
    """Complete risk assessment result."""

    def __init__(
        self,
        overall_risk: int,
        severity: str,
        threats: list[ThreatDetail],
        method: str = "pattern",
        ml_score: int = 0,
        genai_score: Optional[int] = None,
        openai_score: Optional[int] = None,
        openai_explanation: Optional[str] = None,
        openai_confidence: Optional[float] = None,
        processing_time_ms: float = 0,
        cached: bool = False,
    ):
        self.overall_risk = overall_risk
        self.severity = severity
        self.threats = threats
        self.method = method
        self.ml_score = ml_score
        self.genai_score = genai_score
        self.openai_score = openai_score
        self.openai_explanation = openai_explanation
        self.openai_confidence = openai_confidence
        self.processing_time_ms = processing_time_ms
        self.cached = cached

    def to_dict(self) -> dict:
        result: dict[str, Any] = {
            "overall_risk": self.overall_risk,
            "severity": self.severity,
            "method": self.method,
            "ml_score": self.ml_score,
            "threats": [t.to_dict() for t in self.threats],
            "processing_time_ms": round(self.processing_time_ms, 1),
            "cached": self.cached,
        }
        if self.genai_score is not None:
            result["genai_score"] = self.genai_score
        if self.openai_score is not None:
            result["openai_score"] = self.openai_score
            result["openai_explanation"] = self.openai_explanation
            result["openai_confidence"] = self.openai_confidence
        return result


class RiskScorer:
    """Calculates risk scores and generates threat details from pattern matches."""

    def get_severity(self, score: int) -> str:
        """Map a numeric risk score to a severity label."""
        for level, (low, high) in SEVERITY_LEVELS.items():
            if low <= score < high:
                return level
        return "critical"

    def build_threats(self, matches: list) -> list[ThreatDetail]:
        """Convert pattern matches to threat details with Hinglish explanations."""
        threats: list[ThreatDetail] = []
        for m in matches:
            explanation = CATEGORY_EXPLANATIONS.get(
                m.category, "Yeh message suspicious hai. Savdhaan rahein."
            )
            threats.append(
                ThreatDetail(
                    phrase=m.phrase,
                    risk=m.risk,
                    category=m.category,
                    explanation=explanation,
                )
            )
        return threats

    def combine_scores(
        self, pattern_score: int, genai_score: Optional[int]
    ) -> tuple[int, str]:
        """Combine pattern and GenAI scores using weighted logic.

        Returns (final_score, method_used).
        """
        if genai_score is None:
            return pattern_score, "pattern"

        diff = abs(pattern_score - genai_score)
        if diff > 30:
            # Large disagreement — trust GenAI
            final = genai_score
        else:
            # Weighted average: GenAI 70%, Pattern 30%
            final = int(genai_score * 0.7 + pattern_score * 0.3)

        return min(final, 100), "hybrid"

    def score(
        self,
        pattern_score: int,
        matches: list,
        genai_score: Optional[int] = None,
        processing_time_ms: float = 0,
        cached: bool = False,
    ) -> RiskResult:
        """Produce a full risk result from pattern matches and optional GenAI score."""
        final_score, method = self.combine_scores(pattern_score, genai_score)
        severity = self.get_severity(final_score)
        threats = self.build_threats(matches)

        return RiskResult(
            overall_risk=final_score,
            severity=severity,
            threats=threats,
            method=method,
            ml_score=pattern_score,
            genai_score=genai_score,
            processing_time_ms=processing_time_ms,
            cached=cached,
        )
