"""Tests for the Tracemark policy enforcement engine."""

import pytest
from app.policy_engine import (
    PolicyEngine,
    PIIDetectionPolicy,
    TopicBlocklistPolicy,
    ConfidenceThresholdPolicy,
    PolicyType,
    PolicyAction,
    PolicyResult,
)

POLICIES_CONFIG = [
    {
        "id": "pii-detection",
        "name": "PII Detection",
        "enabled": True,
        "type": "BOTH",
        "action": "BLOCK",
        "config": {
            "patterns": [
                {"name": "email", "regex": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"},
                {"name": "phone", "regex": r"(\+?1[\s.-]?)?\(?[0-9]{3}\)?[\s.-]?[0-9]{3}[\s.-]?[0-9]{4}"},
                {"name": "credit_card", "regex": r"[0-9]{4}[\s-]?[0-9]{4}[\s-]?[0-9]{4}[\s-]?[0-9]{4}"},
            ]
        },
    },
    {
        "id": "topic-blocklist",
        "name": "Forbidden Topics",
        "enabled": True,
        "type": "BOTH",
        "action": "BLOCK",
        "config": {
            "forbidden_topics": ["competitor pricing", "legal advice", "medical diagnosis", "insider trading"]
        },
    },
    {
        "id": "confidence-check",
        "name": "Response Confidence Check",
        "enabled": True,
        "type": "POST_CALL",
        "action": "ALLOW_AND_LOG",
        "config": {
            "uncertainty_phrases": ["I am not sure", "I cannot guarantee", "you should consult", "I may be wrong"]
        },
    },
]


@pytest.fixture
def engine():
    return PolicyEngine(POLICIES_CONFIG)


class TestPIIDetection:
    def test_pii_detection_email(self, engine):
        verdicts = engine.evaluate_pre_call("Send email to john@example.com")
        pii = [v for v in verdicts if v.policy_id == "pii-detection"]
        assert len(pii) == 1
        assert pii[0].result == PolicyResult.VIOLATION
        assert "email" in pii[0].matched_rule

    def test_pii_detection_phone(self, engine):
        verdicts = engine.evaluate_pre_call("Call them at (555) 123-4567")
        pii = [v for v in verdicts if v.policy_id == "pii-detection"]
        assert len(pii) == 1
        assert pii[0].result == PolicyResult.VIOLATION
        assert "phone" in pii[0].matched_rule

    def test_pii_no_match(self, engine):
        verdicts = engine.evaluate_pre_call("Summarize the Q3 roadmap for our team")
        pii = [v for v in verdicts if v.policy_id == "pii-detection"]
        assert len(pii) == 1
        assert pii[0].result == PolicyResult.PASS


class TestBlocklist:
    def test_blocklist_match(self, engine):
        verdicts = engine.evaluate_pre_call("What is the competitor pricing for SaaS?")
        bl = [v for v in verdicts if v.policy_id == "topic-blocklist"]
        assert len(bl) == 1
        assert bl[0].result == PolicyResult.VIOLATION
        assert "competitor pricing" in bl[0].matched_rule

    def test_blocklist_no_match(self, engine):
        verdicts = engine.evaluate_pre_call("What are our quarterly sales targets?")
        bl = [v for v in verdicts if v.policy_id == "topic-blocklist"]
        assert len(bl) == 1
        assert bl[0].result == PolicyResult.PASS


class TestConfidence:
    def test_confidence_flag(self, engine):
        verdicts = engine.evaluate_post_call("I am not sure about this recommendation. You should consult an expert.")
        conf = [v for v in verdicts if v.policy_id == "confidence-check"]
        assert len(conf) == 1
        assert conf[0].result == PolicyResult.WARNING
        assert conf[0].details.get("review_required") is True

    def test_confidence_pass(self, engine):
        verdicts = engine.evaluate_post_call("The quarterly revenue increased by 15%.")
        conf = [v for v in verdicts if v.policy_id == "confidence-check"]
        assert len(conf) == 1
        assert conf[0].result == PolicyResult.PASS


class TestEngineOverall:
    def test_blocking_violation_detected(self, engine):
        verdicts = engine.evaluate_pre_call("Email john@test.com about competitor pricing")
        assert engine.has_blocking_violation(verdicts)

    def test_overall_verdict_pass(self, engine):
        verdicts = engine.evaluate_pre_call("What are the Q3 milestones?")
        assert engine.get_overall_verdict(verdicts) == "PASS"

    def test_overall_verdict_blocked(self, engine):
        verdicts = engine.evaluate_pre_call("Send to john@test.com")
        assert engine.get_overall_verdict(verdicts) == "BLOCKED"
