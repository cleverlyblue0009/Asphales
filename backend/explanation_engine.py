"""GenAI validation layer for phishing explanations.

This module never overrides ML risk. It only validates and enriches reasoning.
"""

from __future__ import annotations

import json
import os
from typing import Any

import anthropic


class ExplanationEngine:
    def __init__(self) -> None:
        self.api_key = os.getenv("ANTHROPIC_API_KEY", "")
        self.client = anthropic.Anthropic(api_key=self.api_key) if self.api_key else None

    def _fallback(self, ml_result: dict[str, Any], context_result: dict[str, Any]) -> dict[str, Any]:
        level = context_result["risk_level"]
        signals = context_result.get("detected_signals", [])
        technical = [s for s in signals if "URL" in s or "credential" in s.lower()]
        psych = ["Urgency"] if any("Urgency" in s for s in signals) else []

        return {
            "validation": {
                "risk_alignment": "consistent",
                "false_positive_likelihood": "low" if level in {"HIGH RISK", "CRITICAL"} else "medium",
                "notes": "LLM unavailable; returned deterministic explanation.",
            },
            "explanation": {
                "risk_level": level,
                "primary_reason": ", ".join(signals[:2]) or "No strong phishing signal detected.",
                "psychological_tactics": psych,
                "technical_indicators": technical,
                "confidence": "High" if ml_result["risk_score"] >= 0.8 else "Medium",
            },
        }

    def validate(self, text: str, ml_result: dict[str, Any], detected_features: list[str], links: list[str], context_result: dict[str, Any]) -> dict[str, Any]:
        if not self.client:
            return self._fallback(ml_result, context_result)

        prompt = {
            "text": text,
            "ml_risk_score": ml_result["risk_score"],
            "detected_features": detected_features,
            "links": links,
            "context_result": context_result,
            "rules": [
                "Do not change risk score or class.",
                "Confirm consistency and possible false positives.",
                "Return strict JSON with keys: validation, explanation.",
            ],
        }

        try:
            resp = self.client.messages.create(
                model="claude-3-5-sonnet-latest",
                max_tokens=600,
                messages=[{"role": "user", "content": json.dumps(prompt, ensure_ascii=False)}],
            )
            content = resp.content[0].text
            parsed = json.loads(content)
            return parsed
        except Exception:
            return self._fallback(ml_result, context_result)
