"""PII Detection Policy — scans content for personally identifiable information patterns."""

import re
from typing import Any

from .base import BasePolicy, PolicyVerdict, PolicyResult, PolicyAction, PolicyType


class PIIDetectionPolicy(BasePolicy):
    """Enforces PII detection by scanning for regex-matched patterns (email, phone, credit card)."""

    def __init__(self, policy_id: str, name: str, policy_type: PolicyType,
                 action: PolicyAction, config: dict[str, Any], enabled: bool = True):
        super().__init__(policy_id, name, policy_type, action, config, enabled)
        self.patterns = []
        for p in config.get("patterns", []):
            self.patterns.append({
                "name": p["name"],
                "regex": re.compile(p["regex"]),
            })

    def evaluate(self, content: str) -> PolicyVerdict:
        matches = []
        for pattern in self.patterns:
            found = pattern["regex"].findall(content)
            if found:
                matches.append({
                    "pattern_name": pattern["name"],
                    "match_count": len(found),
                })

        if matches:
            return PolicyVerdict(
                policy_id=self.policy_id,
                policy_name=self.name,
                result=PolicyResult.VIOLATION,
                matched_rule=f"PII detected: {', '.join(m['pattern_name'] for m in matches)}",
                action_taken=self.action,
                details={"matches": matches},
            )

        return PolicyVerdict(
            policy_id=self.policy_id,
            policy_name=self.name,
            result=PolicyResult.PASS,
        )
