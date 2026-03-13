"""EMAIL_SENT compensating action — retracts/flags an AI-generated email."""

import logging
from typing import Any

logger = logging.getLogger("tracemark.remediation.actions")


async def retract_email(context: dict[str, Any]) -> dict[str, Any]:
    """Compensating action: retract an AI-generated email.

    In production, this would integrate with the email provider's API to recall
    the message. For the MVP, this simulates the retraction.
    """
    recipient = context.get("recipient", "unknown")
    subject = context.get("subject", "unknown")

    logger.info(f"RETRACT EMAIL: Retracting email to {recipient} subject='{subject}'")

    # Mock retraction — in production this calls the email provider API
    return {
        "action": "email_retracted",
        "recipient": recipient,
        "subject": subject,
        "retraction_status": "success",
        "message": f"Email to {recipient} has been flagged for retraction",
    }
