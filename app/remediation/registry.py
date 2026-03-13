"""Action Registry — maps AI action types to their compensating actions."""

from __future__ import annotations

import logging
from typing import Any, Callable, Awaitable

logger = logging.getLogger("tracemark.remediation")


class ActionRegistry:
    """Registry mapping action_type strings to (execute_fn, compensate_fn) pairs.

    This implements the core SAGA pattern requirement: every registered action
    has a defined compensating transaction that can reverse its effects.
    """

    def __init__(self):
        self._actions: dict[str, dict[str, Any]] = {}

    def register(
        self,
        action_type: str,
        description: str,
        compensate_fn: Callable[..., Awaitable[dict]],
        notify_compliance: bool = False,
    ):
        self._actions[action_type] = {
            "description": description,
            "compensate_fn": compensate_fn,
            "notify_compliance": notify_compliance,
            "remediation_text": "",
        }
        logger.info(f"Registered compensating action for: {action_type}")

    def get_compensating_action(self, action_type: str) -> Callable[..., Awaitable[dict]] | None:
        entry = self._actions.get(action_type)
        return entry["compensate_fn"] if entry else None

    def should_notify_compliance(self, action_type: str) -> bool:
        entry = self._actions.get(action_type)
        return entry["notify_compliance"] if entry else False

    def is_registered(self, action_type: str) -> bool:
        return action_type in self._actions

    def set_remediation_text(self, action_type: str, text: str) -> bool:
        entry = self._actions.get(action_type)
        if entry:
            entry["remediation_text"] = text
            return True
        return False

    def get_remediation_text(self, action_type: str) -> str:
        entry = self._actions.get(action_type)
        return entry["remediation_text"] if entry else ""

    def list_actions(self) -> list[dict[str, Any]]:
        return [
            {
                "action_type": action_type,
                "description": info["description"],
                "notify_compliance": info["notify_compliance"],
                "remediation_text": info.get("remediation_text", ""),
            }
            for action_type, info in self._actions.items()
        ]
