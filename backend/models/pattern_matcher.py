"""Rule-based pattern matching for phishing detection in code-mixed Hindi-English text."""

import json
import re
from pathlib import Path
from typing import Optional

PATTERNS_FILE = Path(__file__).parent / "patterns.json"


class PatternMatch:
    """Represents a single pattern match found in text."""

    def __init__(self, phrase: str, risk: int, category: str, position: int):
        self.phrase = phrase
        self.risk = risk
        self.category = category
        self.position = position

    def to_dict(self) -> dict:
        return {
            "phrase": self.phrase,
            "risk": self.risk,
            "category": self.category,
            "position": self.position,
        }


class PatternMatcher:
    """Detects phishing patterns in code-mixed Hindi-English messages using
    rule-based keyword and regex matching."""

    def __init__(self, patterns_file: Optional[str] = None):
        path = Path(patterns_file) if patterns_file else PATTERNS_FILE
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.categories: dict = data["categories"]
        self.patterns: list[dict] = data["patterns"]
        self._compiled: list[tuple[re.Pattern, dict]] = []
        for p in self.patterns:
            regex = re.compile(re.escape(p["text"]), re.IGNORECASE)
            self._compiled.append((regex, p))

    def match(self, text: str) -> list[PatternMatch]:
        """Find all matching phishing patterns in the given text."""
        matches: list[PatternMatch] = []
        text_lower = text.lower()
        seen_phrases: set[str] = set()
        for regex, pattern in self._compiled:
            m = regex.search(text_lower)
            if m and pattern["text"] not in seen_phrases:
                seen_phrases.add(pattern["text"])
                matches.append(
                    PatternMatch(
                        phrase=pattern["text"],
                        risk=pattern["risk"],
                        category=pattern["category"],
                        position=m.start(),
                    )
                )
        return matches

    def calculate_score(self, matches: list[PatternMatch]) -> int:
        """Calculate an overall risk score from the matched patterns.

        Uses category weights and takes the weighted maximum across matches,
        then blends with coverage factor.
        """
        if not matches:
            return 0

        weighted_risks: list[float] = []
        for m in matches:
            cat_weight = self.categories.get(m.category, {}).get("weight", 0.5)
            weighted_risks.append(m.risk * cat_weight)

        max_risk = max(weighted_risks)
        avg_risk = sum(weighted_risks) / len(weighted_risks)
        # More matches increase confidence
        coverage_bonus = min(len(matches) * 3, 15)
        score = int(max_risk * 0.7 + avg_risk * 0.3 + coverage_bonus)
        return min(score, 100)

    def get_categories_matched(self, matches: list[PatternMatch]) -> list[str]:
        """Return unique categories found in matches."""
        return list({m.category for m in matches})

    def get_pattern_count(self) -> int:
        """Return total number of loaded patterns."""
        return len(self.patterns)

    def get_patterns_by_category(self, category: str) -> list[dict]:
        """Return patterns filtered by category."""
        return [p for p in self.patterns if p["category"] == category]
