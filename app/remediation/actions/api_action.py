"""API_CALL_MADE compensating action — revokes or rolls back an external API call."""

import logging
from typing import Any

logger = logging.getLogger("tracemark.remediation.actions")


async def revoke_api_call(context: dict[str, Any]) -> dict[str, Any]:
    """Compensating action: revoke or roll back an AI-initiated external API call.

    In production, this would call the target API's undo/cancel endpoint.
    For the MVP, this simulates the rollback.
    """
    endpoint = context.get("endpoint", "unknown")
    method = context.get("method", "POST")
    request_id = context.get("request_id", "unknown")

    logger.info(f"REVOKE API CALL: Rolling back {method} {endpoint} (req: {request_id})")

    return {
        "action": "api_call_revoked",
        "endpoint": endpoint,
        "method": method,
        "request_id": request_id,
        "revocation_status": "success",
        "message": f"API call to {endpoint} has been revoked",
    }
