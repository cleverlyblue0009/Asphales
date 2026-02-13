"""Unit tests for the classifier components."""

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from models.pattern_matcher import PatternMatcher
from models.risk_scorer import RiskScorer
from services.cache_manager import CacheManager
from utils.text_processor import (
    detect_language,
    normalize,
    preprocess,
    text_hash,
    validate_length,
)


# ---------- PatternMatcher ----------

class TestPatternMatcher:
    def setup_method(self):
        self.matcher = PatternMatcher()

    def test_pattern_count(self):
        assert self.matcher.get_pattern_count() >= 50

    def test_detects_password(self):
        matches = self.matcher.match("password share karo")
        assert len(matches) >= 1
        assert any(m.phrase == "password share karo" for m in matches)

    def test_detects_otp(self):
        matches = self.matcher.match("turant otp batao")
        assert any("otp" in m.phrase for m in matches)

    def test_detects_multiple(self):
        matches = self.matcher.match("password share karo aur otp bhejo turant verify karo")
        assert len(matches) >= 3

    def test_safe_message(self):
        matches = self.matcher.match("kal meeting hai office mein")
        assert len(matches) == 0

    def test_score_no_matches(self):
        assert self.matcher.calculate_score([]) == 0

    def test_score_with_matches(self):
        matches = self.matcher.match("password share karo aur otp bhejo")
        score = self.matcher.calculate_score(matches)
        assert score > 50

    def test_case_insensitive(self):
        matches = self.matcher.match("PASSWORD SHARE KARO")
        assert len(matches) >= 1

    def test_categories(self):
        matches = self.matcher.match("cvv batao")
        categories = self.matcher.get_categories_matched(matches)
        assert "credential_request" in categories


# ---------- RiskScorer ----------

class TestRiskScorer:
    def setup_method(self):
        self.scorer = RiskScorer()

    def test_severity_low(self):
        assert self.scorer.get_severity(10) == "low"

    def test_severity_medium(self):
        assert self.scorer.get_severity(45) == "medium"

    def test_severity_high(self):
        assert self.scorer.get_severity(75) == "high"

    def test_severity_critical(self):
        assert self.scorer.get_severity(90) == "critical"

    def test_combine_pattern_only(self):
        score, method = self.scorer.combine_scores(80, None)
        assert score == 80
        assert method == "pattern"

    def test_combine_hybrid(self):
        score, method = self.scorer.combine_scores(70, 80)
        assert method == "hybrid"
        # Weighted: 80*0.7 + 70*0.3 = 77
        assert score == 77

    def test_combine_large_diff(self):
        score, method = self.scorer.combine_scores(20, 80)
        assert score == 80  # Trusts GenAI when diff > 30


# ---------- CacheManager ----------

class TestCacheManager:
    def test_set_get(self):
        cache = CacheManager()
        cache.set("key1", {"risk": 50})
        assert cache.get("key1") == {"risk": 50}

    def test_miss(self):
        cache = CacheManager()
        assert cache.get("nonexistent") is None

    def test_eviction(self):
        cache = CacheManager(max_size=2)
        cache.set("a", 1)
        cache.set("b", 2)
        cache.set("c", 3)
        assert cache.get("a") is None
        assert cache.get("b") == 2
        assert cache.get("c") == 3

    def test_stats(self):
        cache = CacheManager()
        cache.set("x", 1)
        cache.get("x")
        cache.get("y")
        stats = cache.stats()
        assert stats["hits"] == 1
        assert stats["misses"] == 1


# ---------- TextProcessor ----------

class TestTextProcessor:
    def test_normalize(self):
        assert normalize("  HELLO  World  ") == "hello world"

    def test_detect_english(self):
        assert detect_language("Hello world") == "english"

    def test_detect_mixed(self):
        assert detect_language("Hello दुनिया") == "mixed"

    def test_detect_hindi(self):
        assert detect_language("नमस्ते दुनिया") == "hindi"

    def test_hash_consistent(self):
        h1 = text_hash("test message")
        h2 = text_hash("test message")
        assert h1 == h2

    def test_hash_different(self):
        h1 = text_hash("message A")
        h2 = text_hash("message B")
        assert h1 != h2

    def test_validate_empty(self):
        ok, _ = validate_length("")
        assert not ok

    def test_validate_too_long(self):
        ok, _ = validate_length("a" * 6000)
        assert not ok

    def test_validate_ok(self):
        ok, _ = validate_length("normal message")
        assert ok

    def test_preprocess(self):
        assert preprocess("  HELLO  World!  ") == "hello world!"
