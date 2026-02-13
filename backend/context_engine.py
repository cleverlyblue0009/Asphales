"""Context-aware risk scoring for phishing detection."""

from __future__ import annotations

import re
from typing import Any

URL_RE = re.compile(r"https?://\S+", re.IGNORECASE)
IP_URL_RE = re.compile(r"https?://(?:\d{1,3}\.){3}\d{1,3}(?:[:/]\S*)?", re.IGNORECASE)
SHORTENER_RE = re.compile(r"https?://(?:bit\.ly|tinyurl\.com|t\.co|goo\.gl)/\S+", re.IGNORECASE)
SUSPICIOUS_TLD_RE = re.compile(r"https?://[^\s]+\.(?:top|xyz|click|gq|tk|work|fit|site|link)(?:/|$)", re.IGNORECASE)

URGENCY_TERMS = {"urgent", "immediately", "now", "final warning", "तुरंत", "இப்போது", "এখনই", "urg3nt", "immediate"}
IMPERSONATION_TERMS = {"bank", "rbi", "sbi", "hdfc", "icici", "support team", "security desk", "customer care"}
CREDENTIAL_TERMS = {"otp", "password", "pin", "cvv", "credential", "verify account", "kyc", "login"}
ACTION_TERMS = {"click", "tap", "open", "verify", "share", "submit", "update", "enter"}
BENIGN_CONTEXT_TERMS = {
    # Educational
    "fixture", "score", "style", "match", "players", "schedule", "tournament", "semester", "admission",
    "class", "project", "notice", "agenda", "minutes", "invoice", "receipt", "weather", "festival",
    "homework", "assignment", "exam", "test", "quiz", "lecture", "tutorial", "lab", "practical",
    "university", "college", "school", "student", "teacher", "professor", "fresher", "freshers",
    "semester", "grade", "marks", "result", "transcript", "certificate", "degree", "course",
    # Sports & Events
    "cricket", "football", "basketball", "badminton", "tennis", "sport", "game", "team", "coach",
    "tournament", "championship", "league", "cup", "final", "semifinal", "qualifier", "match",
    "fixture", "venue", "stadium", "ground", "player", "captain", "wicket", "goal", "run", "over",
    # Social
    "friend", "family", "birthday", "party", "celebration", "meeting", "reunion", "gathering",
    "wedding", "engagement", "anniversary", "festival", "holiday", "vacation", "trip", "travel",
    # Work/Professional
    "meeting", "agenda", "presentation", "conference", "workshop", "training", "seminar", "webinar",
    "deadline", "report", "document", "file", "folder", "email", "memo", "notice", "circular",
    # Food & Lifestyle
    "restaurant", "cafe", "food", "lunch", "dinner", "breakfast", "recipe", "cooking", "menu",
    "movie", "film", "show", "series", "episode", "season", "theater", "cinema", "netflix",
    # Informational
    "format", "style", "design", "layout", "template", "guide", "tutorial", "instructions", "steps",
    "example", "sample", "demo", "showcase", "preview", "overview", "summary", "description",
    # Location names (common false positives)
    "vellore", "chennai", "bangalore", "mumbai", "delhi", "hyderabad", "pune", "kolkata",
    "vit", "iit", "nit", "bits", "manipal", "srm", "amrita", "anna university"
}


def classify_risk_level(score: float) -> str:
    """
    Classify risk level based on score.
    Updated thresholds for better accuracy:
    - LOW RISK: < 0.45 (most benign content)
    - MEDIUM RISK: 0.45 - 0.75 (suspicious but uncertain)
    - HIGH RISK: >= 0.75 (clear phishing patterns)
    """
    if score < 0.45:
        return "LOW RISK"
    if score < 0.75:
        return "MEDIUM RISK"
    return "HIGH RISK"


def extract_links(text: str) -> list[str]:
    return URL_RE.findall(text or "")


def _has_any(text_l: str, terms: set[str]) -> bool:
    return any(t in text_l for t in terms)


def _is_suspicious_link(link: str) -> bool:
    return bool(IP_URL_RE.search(link) or SHORTENER_RE.search(link) or SUSPICIOUS_TLD_RE.search(link))


def calculate_contextual_risk(text: str, detected_features: list[str] | None, links: list[str] | None, base_score: float = 0.0) -> dict[str, Any]:
    text = text or ""
    text_l = text.lower()
    links = links or extract_links(text)
    detected_features = detected_features or []

    boosts = 0.0
    dampener = 0.0
    signals: list[str] = list(detected_features)

    urgency = _has_any(text_l, URGENCY_TERMS)
    impersonation = _has_any(text_l, IMPERSONATION_TERMS)
    credential_req = _has_any(text_l, CREDENTIAL_TERMS)
    action_prompt = _has_any(text_l, ACTION_TERMS)
    benign_context = _has_any(text_l, BENIGN_CONTEXT_TERMS)

    suspicious_links = [l for l in links if _is_suspicious_link(l)]

    if urgency and credential_req:
        boosts += 0.12
        signals.append("Urgency + credential ask")

    if impersonation and (credential_req or action_prompt):
        boosts += 0.10
        signals.append("Brand impersonation")

    if action_prompt and links:
        boosts += 0.08
        signals.append("Action request with link")

    if suspicious_links:
        boosts += 0.14
        signals.append("Suspicious URL structure")

    sentences = [s.strip() for s in re.split(r"[.!?\n]+", text_l) if s.strip()]
    for i in range(max(0, len(sentences) - 1)):
        a, b = sentences[i], sentences[i + 1]
        if (_has_any(a, URGENCY_TERMS) and _has_any(b, CREDENTIAL_TERMS | ACTION_TERMS)) or (
            _has_any(a, IMPERSONATION_TERMS) and _has_any(b, CREDENTIAL_TERMS | ACTION_TERMS)
        ):
            boosts += 0.10
            signals.append("Context chain: pressure → action")
            break

    # Strong dampener for clearly benign content
    if benign_context:
        if not suspicious_links and not (urgency and credential_req):
            dampener += 0.25  # Increased from 0.15
            signals.append("Benign-topic dampener")
        elif not suspicious_links:
            # Even if some risk signals, but no suspicious links, dampen moderately
            dampener += 0.15
            signals.append("Likely benign context")

    # Keep isolated risky words from over-triggering.
    if not suspicious_links and sum([urgency, impersonation, credential_req, action_prompt]) <= 1:
        dampener += 0.18  # Increased from 0.12
        signals.append("Isolated keyword (low confidence)")

    final = max(0.0, min(1.0, base_score + boosts - dampener))
    return {
        "risk_score": round(final, 4),
        "risk_level": classify_risk_level(final),
        "detected_signals": sorted(set(signals)),
        "context_boost": round(boosts - dampener, 4),
        "suspicious_links": suspicious_links,
    }
