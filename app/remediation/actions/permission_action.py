"""PERMISSION_CHANGED compensating action — reverts an AI-initiated permission change."""

import logging
from typing import Any

logger = logging.getLogger("tracemark.remediation.actions")


async def revert_permission_change(context: dict[str, Any]) -> dict[str, Any]:
    """Compensating action: revert a permission change made by AI.

    In production, this would call the IAM/RBAC system to restore the previous
    permission set. For the MVP, this simulates the revert.
    """
    user_id = context.get("user_id", "unknown")
    resource = context.get("resource", "unknown")
    previous_role = context.get("previous_role", "viewer")
    changed_to = context.get("changed_to", "unknown")

    logger.info(
        f"REVERT PERMISSION: Reverting {user_id} on {resource} from {changed_to} to {previous_role}"
    )

    return {
        "action": "permission_reverted",
        "user_id": user_id,
        "resource": resource,
        "reverted_from": changed_to,
        "reverted_to": previous_role,
        "revert_status": "success",
        "message": f"Permission for {user_id} on {resource} reverted to {previous_role}",
    }
