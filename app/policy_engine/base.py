"""Base policy classes and data types for the Tracemark policy enforcement engine."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class PolicyType(str, Enum):
    PRE_CALL = "PRE_CALL"
    POST_CALL = "POST_CALL"
    BOTH = "BOTH"


class PolicyAction(str, Enum):
    BLOCK = "BLOCK"
    TRANSFORM = "TRANSFORM"
    ALLOW_AND_LOG = "ALLOW_AND_LOG"
    REMEDIATE = "REMEDIATE"


class PolicyResult(str, Enum):
    PASS = "PASS"
    VIOLATION = "VIOLATION"
    WARNING = "WARNING"


@dataclass
class PolicyVerdict:
    policy_id: str
    policy_name: str
    result: PolicyResult
    matched_rule: str | None = None
    action_taken: PolicyAction | None = None
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "policy_id": self.policy_id,
            "policy_name": self.policy_name,
            "result": self.result.value,
            "matched_rule": self.matched_rule,
            "action_taken": self.action_taken.value if self.action_taken else None,
            "details": self.details,
        }


class BasePolicy(ABC):
    """Abstract base class for all Tracemark policy implementations."""

    def __init__(self, policy_id: str, name: str, policy_type: PolicyType,
                 action: PolicyAction, config: dict[str, Any], enabled: bool = True):
        self.policy_id = policy_id
        self.name = name
        self.policy_type = policy_type
        self.action = action
        self.config = config
        self.enabled = enabled
        self.remediation_text = ""

    @abstractmethod
    def evaluate(self, content: str) -> PolicyVerdict:
        """Evaluate content against this policy and return a verdict."""
        ...

    def applies_to_phase(self, phase: str) -> bool:
        """Check if this policy applies to the given phase (PRE_CALL or POST_CALL)."""
        if not self.enabled:
            return False
        if self.policy_type == PolicyType.BOTH:
            return True
        return self.policy_type.value == phase
