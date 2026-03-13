"""Topic Blocklist Policy — enforces forbidden topic restrictions."""

from typing import Any

from .base import BasePolicy, PolicyVerdict, PolicyResult, PolicyAction, PolicyType


class TopicBlocklistPolicy(BasePolicy):
    """Enforces topic blocklisting by scanning content for forbidden topic strings."""

    def __init__(self, policy_id: str, name: str, policy_type: PolicyType,
                 action: PolicyAction, config: dict[str, Any], enabled: bool = True):
        super().__init__(policy_id, name, policy_type, action, config, enabled)
        self.forbidden_topics = [t.lower() for t in config.get("forbidden_topics", [])]

    def evaluate(self, content: str) -> PolicyVerdict:
        content_lower = content.lower()
        matched_topics = [
            topic for topic in self.forbidden_topics if topic in content_lower
        ]

        if matched_topics:
            return PolicyVerdict(
                policy_id=self.policy_id,
                policy_name=self.name,
                result=PolicyResult.VIOLATION,
                matched_rule=f"Forbidden topic detected: {', '.join(matched_topics)}",
                action_taken=self.action,
                details={"matched_topics": matched_topics},
            )

        return PolicyVerdict(
            policy_id=self.policy_id,
            policy_name=self.name,
            result=PolicyResult.PASS,
        )
