"""OpenAI-based phishing analysis with detailed explanations."""

import json
import os
from typing import Optional

from utils.logger import setup_logger

logger = setup_logger("openai_analyzer")

try:
    from openai import OpenAI, APITimeoutError, RateLimitError, AuthenticationError
    HAS_OPENAI = True
except ImportError:
    HAS_OPENAI = False
    logger.warning("OpenAI library not installed. GenAI features disabled.")


OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
ENABLE_OPENAI = os.getenv("ENABLE_OPENAI", "true").lower() == "true"
OPENAI_TIMEOUT = int(os.getenv("OPENAI_TIMEOUT", "8"))


class OpenAIPhishingAnalyzer:
    """Analyzes phishing texts using OpenAI API."""

    def __init__(self):
        self.enabled = ENABLE_OPENAI and HAS_OPENAI and OPENAI_API_KEY
        self.client = None
        if self.enabled:
            try:
                self.client = OpenAI(api_key=OPENAI_API_KEY, timeout=OPENAI_TIMEOUT)
                logger.info("OpenAI analyzer initialized successfully")
            except Exception as e:
                logger.error(f"Failed to initialize OpenAI client: {e}")
                self.enabled = False

    async def analyze(self, text: str, language: str = "English") -> Optional[dict]:
        """
        Analyze text for phishing using OpenAI.

        Returns:
            dict with keys: is_phishing, risk_score, explanation, tactics, confidence
        """
        if not self.enabled:
            return None

        try:
            system_prompt = f"""You are an expert cybersecurity analyst specializing in detecting phishing, scams, and malicious messages in {language}.

Analyze the provided message carefully and respond with a JSON object containing:
1. is_phishing (boolean): True if phishing/scam detected
2. risk_score (int 0-100): Severity of threat
3. explanation (string): Clear, concise explanation of why it's suspicious (in English)
4. explanation_vernacular (string): Same explanation in {language} if applicable
5. tactics (array): List of manipulation tactics detected (urgency, fear, greed, authority, credential harvesting, etc.)
6. technical_indicators (array): Technical red flags (suspicious links, spoofed domains, malware indicators, etc.)
7. confidence (float 0.0-1.0): How confident in the assessment

For safe messages, set is_phishing=false, risk_score <30, and explain why it's safe.
For suspicious messages, be specific about what makes it dangerous.
Always provide actionable insights for the user."""

            user_message = f"""Analyze this message for phishing and scams:

"{text}"

Provide a detailed security assessment in JSON format."""

            response = self.client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_message},
                ],
                temperature=0.3,
                max_tokens=500,
                timeout=OPENAI_TIMEOUT,
            )

            response_text = response.choices[0].message.content.strip()

            # Extract JSON from response
            json_start = response_text.find("{")
            json_end = response_text.rfind("}") + 1
            if json_start >= 0 and json_end > json_start:
                json_str = response_text[json_start:json_end]
                result = json.loads(json_str)

                # Validate response structure
                if self._validate_response(result):
                    logger.info(f"OpenAI analysis completed: risk_score={result.get('risk_score')}")
                    return result
            else:
                logger.warning(f"Could not find JSON in OpenAI response: {response_text}")
                return None

        except APITimeoutError:
            logger.warning("OpenAI API timeout - proceeding with ML-only detection")
            return None
        except AuthenticationError:
            logger.error("OpenAI authentication failed - check API key")
            self.enabled = False
            return None
        except RateLimitError:
            logger.warning("OpenAI rate limit exceeded - retrying next request")
            return None
        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse OpenAI JSON response: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error in OpenAI analysis: {e}")
            return None

    @staticmethod
    def _validate_response(response: dict) -> bool:
        """Validate OpenAI response structure."""
        required_fields = [
            "is_phishing",
            "risk_score",
            "explanation",
            "tactics",
            "confidence",
        ]
        for field in required_fields:
            if field not in response:
                return False

        # Validate risk_score is 0-100
        try:
            risk = int(response.get("risk_score", 0))
            if not (0 <= risk <= 100):
                return False
        except (ValueError, TypeError):
            return False

        # Validate confidence is 0.0-1.0
        try:
            conf = float(response.get("confidence", 0.5))
            if not (0.0 <= conf <= 1.0):
                return False
        except (ValueError, TypeError):
            return False

        return True

    def get_info(self) -> dict:
        """Get analyzer status info."""
        return {
            "name": "OpenAI Analyzer",
            "enabled": self.enabled,
            "model": "gpt-4o-mini",
            "api_key_configured": bool(OPENAI_API_KEY),
            "has_library": HAS_OPENAI,
        }
