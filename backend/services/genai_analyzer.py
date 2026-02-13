"""Claude AI integration for contextual phishing analysis of code-mixed messages."""

import json
import os
from typing import Any, Optional

import anthropic

from utils.logger import setup_logger

logger = setup_logger("genai_analyzer")

SYSTEM_PROMPT = """You are SurakshaAI, a phishing detection expert specializing in multilingual Indian code-mixed messages (English + 22 official Indian languages) common in India. Analyze the given message for phishing indicators.

You MUST respond with valid JSON only — no other text. Use this exact schema:

{
  "risk_score": <int 0-100>,
  "is_phishing": <bool>,
  "tactics": [<list of tactic strings detected>],
  "explanation_hinglish": "<2-3 sentence explanation in Hinglish>",
  "confidence": <float 0.0-1.0>
}

Detection guidelines:
- Urgency tactics: "turant", "abhi", "jaldi", time pressure
- Credential harvesting: requesting password, OTP, PIN, CVV
- Impersonation: pretending to be bank, government, police, RBI
- Fear/threats: account block, arrest, legal action, FIR
- Too-good-to-be-true: lottery, prize, crore rupaye, free gifts
- Money requests: processing fee, registration fee, advance payment
- Personal info requests: Aadhar, PAN, bank account number
- Suspicious links: shortened URLs, unknown domains

Cultural context:
- Indian banking scams often use code-mixed language and transliteration
- Common targets: UPI (GPay, PhonePe, Paytm), Aadhar, PAN card
- Government impersonation is very common (Income Tax, RBI, Police)

Language coverage:
- Handle all 22 official Indian languages and code-mixed Romanized writing: Assamese, Bengali, Bodo, Dogri, Gujarati, Hindi, Kannada, Kashmiri, Konkani, Maithili, Malayalam, Manipuri, Marathi, Nepali, Odia, Punjabi, Sanskrit, Santali, Sindhi, Tamil, Telugu, Urdu.
- Detect English mixed with any of the above scripts/transliterations (Indian texting style).
- Treat semantic equivalents of OTP/password/KYC/account block across these languages as suspicious.
"""

USER_PROMPT_TEMPLATE = """Analyze this message for phishing:

"{text}"

Respond with JSON only."""


class GenAIAnalyzer:
    """Uses Claude API to perform contextual phishing analysis."""

    def __init__(self):
        self.api_key: Optional[str] = os.getenv("ANTHROPIC_API_KEY")
        self.enabled: bool = os.getenv("ENABLE_GENAI", "true").lower() == "true"
        self.timeout: int = int(os.getenv("GENAI_TIMEOUT", "5"))
        self.model: str = "claude-sonnet-4-20250514"
        self.client: Optional[anthropic.Anthropic] = None

        if self.api_key and self.enabled:
            self.client = anthropic.Anthropic(
                api_key=self.api_key,
                timeout=self.timeout,
            )
            logger.info("GenAI analyzer initialized with Claude API")
        else:
            logger.warning(
                "GenAI analyzer disabled — %s",
                "no API key" if not self.api_key else "disabled by config",
            )

    def is_available(self) -> bool:
        """Check whether the GenAI analyzer can be used."""
        return self.client is not None and self.enabled

    async def analyze(self, text: str) -> Optional[dict[str, Any]]:
        """Send text to Claude for phishing analysis.

        Returns parsed JSON result or None on failure.
        """
        if not self.is_available():
            logger.debug("GenAI not available, skipping analysis")
            return None

        try:
            response = self.client.messages.create(
                model=self.model,
                max_tokens=512,
                system=SYSTEM_PROMPT,
                messages=[
                    {
                        "role": "user",
                        "content": USER_PROMPT_TEMPLATE.format(text=text),
                    }
                ],
            )

            raw = response.content[0].text.strip()
            # Strip markdown code fences if present
            if raw.startswith("```"):
                lines = raw.split("\n")
                raw = "\n".join(lines[1:-1]) if len(lines) > 2 else raw

            result = json.loads(raw)
            logger.info(
                "GenAI analysis complete — risk_score=%s, confidence=%s",
                result.get("risk_score"),
                result.get("confidence"),
            )
            return self._validate(result)

        except json.JSONDecodeError as exc:
            logger.error("Failed to parse GenAI response as JSON: %s", exc)
            return None
        except anthropic.APITimeoutError:
            logger.warning("GenAI request timed out after %ss", self.timeout)
            return None
        except anthropic.AuthenticationError:
            logger.error("Invalid Anthropic API key")
            return None
        except anthropic.RateLimitError:
            logger.warning("Rate limited by Anthropic API")
            return None
        except Exception as exc:
            logger.error("GenAI analysis failed: %s", exc)
            return None

    def _validate(self, result: dict) -> Optional[dict]:
        """Ensure the GenAI response has the expected fields."""
        required = {"risk_score", "is_phishing", "tactics", "explanation_hinglish", "confidence"}
        if not required.issubset(result.keys()):
            logger.warning("GenAI response missing fields: %s", required - result.keys())
            return None

        risk = result["risk_score"]
        if not isinstance(risk, (int, float)) or not (0 <= risk <= 100):
            logger.warning("Invalid risk_score from GenAI: %s", risk)
            return None

        result["risk_score"] = int(result["risk_score"])
        return result
