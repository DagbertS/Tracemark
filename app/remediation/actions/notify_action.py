"""NOTIFICATION_SENT compensating action — sends override notification to compliance."""

import logging
from typing import Any

logger = logging.getLogger("tracemark.remediation.actions")


async def send_compliance_override(context: dict[str, Any]) -> dict[str, Any]:
    """Compensating action: send an override notification to the compliance team.

    In production, this would integrate with the enterprise notification system
    (Slack, email, PagerDuty, etc.). For the MVP, this simulates the notification.
    """
    original_notification = context.get("notification_type", "unknown")
    recipient = context.get("recipient", "compliance-team")

    logger.info(
        f"COMPLIANCE OVERRIDE: Sending override for '{original_notification}' to {recipient}"
    )

    return {
        "action": "compliance_override_sent",
        "original_notification": original_notification,
        "override_sent_to": recipient,
        "override_status": "success",
        "message": f"Compliance override notification sent to {recipient}",
    }
