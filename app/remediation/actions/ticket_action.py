"""TICKET_CREATED compensating action — closes or voids an AI-created support ticket."""

import logging
from typing import Any

logger = logging.getLogger("tracemark.remediation.actions")


async def void_ticket(context: dict[str, Any]) -> dict[str, Any]:
    """Compensating action: void a support ticket created by AI.

    In production, this would call the ticketing system API (Jira, Zendesk, etc.)
    to close or void the ticket. For the MVP, this simulates the voiding.
    """
    ticket_id = context.get("ticket_id", "unknown")
    system = context.get("system", "internal")
    assigned_to = context.get("assigned_to", "unassigned")

    logger.info(f"VOID TICKET: Voiding ticket {ticket_id} in {system}")

    return {
        "action": "ticket_voided",
        "ticket_id": ticket_id,
        "system": system,
        "assigned_to": assigned_to,
        "void_status": "success",
        "message": f"Ticket {ticket_id} in {system} has been voided",
    }
