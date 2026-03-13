"""CRM_UPDATED compensating action — restores a CRM record to its previous state."""

import logging
from typing import Any

logger = logging.getLogger("tracemark.remediation.actions")


async def restore_crm_record(context: dict[str, Any]) -> dict[str, Any]:
    """Compensating action: restore a CRM record modified by AI.

    In production, this would call the CRM API to restore the previous field values.
    For the MVP, this simulates the restoration.
    """
    record_id = context.get("record_id", "unknown")
    field_name = context.get("field_name", "unknown")
    previous_value = context.get("previous_value", "unknown")

    logger.info(
        f"RESTORE CRM: Restoring record {record_id} field '{field_name}' "
        f"to previous value '{previous_value}'"
    )

    return {
        "action": "crm_record_restored",
        "record_id": record_id,
        "field_name": field_name,
        "restored_to": previous_value,
        "restoration_status": "success",
        "message": f"CRM record {record_id} restored to previous state",
    }
