"""Response Confidence Check Policy — flags responses containing uncertainty signals."""

from typing import Any

from .base import BasePolicy, PolicyVerdict, PolicyResult, PolicyAction, PolicyType


class ConfidenceThresholdPolicy(BasePolicy):
    """Enforces confidence thresholds by detecting uncertainty language in model responses."""

    def __init__(self, policy_id: str, name: str, policy_type: PolicyType,
                 action: PolicyAction, config: dict[str, Any], enabled: bool = True):
        super().__init__(policy_id, name, policy_type, action, config, enabled)
        self.uncertainty_phrases = [
            p.lower() for p in config.get("uncertainty_phrases", [])
        ]

    def evaluate(self, content: str) -> PolicyVerdict:
        content_lower = content.lower()
        matched_phrases = [
            phrase for phrase in self.uncertainty_phrases if phrase in content_lower
        ]

        if matched_phrases:
            return PolicyVerdict(
                policy_id=self.policy_id,
                policy_name=self.name,
                result=PolicyResult.WARNING,
                matched_rule=f"Uncertainty detected: {', '.join(matched_phrases)}",
                action_taken=PolicyAction.ALLOW_AND_LOG,
                details={
                    "matched_phrases": matched_phrases,
                    "review_required": True,
                },
            )

        return PolicyVerdict(
            policy_id=self.policy_id,
            policy_name=self.name,
            result=PolicyResult.PASS,
        )
