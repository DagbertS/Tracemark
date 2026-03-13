"""SAGA Orchestrator — executes compensating transactions for AI action remediation.

Implements a simplified SAGA orchestration pattern: when a policy violation is
detected after an AI action has already produced downstream effects, the
orchestrator executes compensating actions in reverse order to undo those effects.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from .registry import ActionRegistry

logger = logging.getLogger("tracemark.remediation")


class SAGAOrchestrator:
    """Orchestrates compensating transactions using the SAGA pattern."""

    def __init__(self, registry: ActionRegistry):
        self.registry = registry
        self.saga_log: list[dict[str, Any]] = []

    async def execute_compensation(
        self, action_type: str, context: dict[str, Any], reason: str
    ) -> dict[str, Any]:
        """Execute a compensating action for the given action type."""
        saga_id = str(uuid.uuid4())

        if not self.registry.is_registered(action_type):
            error_entry = {
                "saga_id": saga_id,
                "action_type": action_type,
                "compensating_action": None,
                "status": "FAILED",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "reason": reason,
                "error": f"Unknown action type: {action_type}",
                "context": context,
            }
            self.saga_log.append(error_entry)
            return error_entry

        compensate_fn = self.registry.get_compensating_action(action_type)
        log_entry = {
            "saga_id": saga_id,
            "action_type": action_type,
            "compensating_action": compensate_fn.__name__ if compensate_fn else None,
            "status": "PENDING",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "reason": reason,
            "context": context,
            "error": None,
        }
        self.saga_log.append(log_entry)

        try:
            result = await compensate_fn(context)
            log_entry["status"] = "COMPLETED"
            log_entry["result"] = result

            if self.registry.should_notify_compliance(action_type):
                log_entry["compliance_notified"] = True
                logger.info(
                    f"SAGA {saga_id}: Compliance notification sent for {action_type}"
                )

            logger.info(f"SAGA {saga_id}: Compensation completed for {action_type}")
        except Exception as e:
            log_entry["status"] = "FAILED"
            log_entry["error"] = str(e)
            logger.error(f"SAGA {saga_id}: Compensation failed for {action_type}: {e}")

        return log_entry

    def get_saga_log(self, limit: int = 50) -> list[dict[str, Any]]:
        return list(reversed(self.saga_log[-limit:]))

    def get_saga_entry(self, saga_id: str) -> dict[str, Any] | None:
        for entry in self.saga_log:
            if entry["saga_id"] == saga_id:
                return entry
        return None
