"""Unit tests for ML + GenAI classifier components."""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from models.risk_scorer import RiskScorer
from services.classifier import HybridClassifier
from services.ml_classifier import MLPhishingClassifier
from utils.text_processor import validate_length


class TestMLClassifier:
    def setup_method(self):
        self.clf = MLPhishingClassifier()

    def test_model_info(self):
        info = self.clf.get_info()
        assert info["dataset_exists"] is True

    def test_detects_phishing(self):
        msg = "Your SBI account will be blocked. Verify KYC now and enter OTP"
        result = self.clf.predict(msg)
        assert result["risk_score"] >= 55
        assert result["is_phishing"] is True

    def test_detects_safe(self):
        msg = "Team meeting is at 4 PM, please bring project notes"
        result = self.clf.predict(msg)
        assert result["risk_score"] < 55


class TestRiskScorer:
    def setup_method(self):
        self.scorer = RiskScorer()

    def test_severity_levels(self):
        assert self.scorer.get_severity(10) == "low"
        assert self.scorer.get_severity(45) == "medium"
        assert self.scorer.get_severity(70) == "high"
        assert self.scorer.get_severity(95) == "critical"


class TestInputValidation:
    def test_validate_empty(self):
        ok, _ = validate_length("")
        assert not ok

    def test_validate_too_long(self):
        ok, _ = validate_length("a" * 6000)
        assert not ok

    def test_validate_ok(self):
        ok, _ = validate_length("normal message")
        assert ok


@pytest.mark.asyncio
async def test_line_level_aggregator_catches_phishy_line_in_long_text():
    clf = HybridClassifier()
    text = """23BCB0058
23BCB0155
Dear Customer,
Your SBI account will be blocked within 24 hours due to suspicious activity.
Please verify your KYC immediately to avoid permanent suspension.
Click here and enter your OTP and debit card details to continue
SJT 308 Biochemistry
Payment Guitar Sir No.
"""

    result = await clf.classify(text)
    assert result.overall_risk >= 60
    assert len(result.threats) > 0
