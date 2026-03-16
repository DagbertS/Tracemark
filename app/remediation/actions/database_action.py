"""DATABASE_MODIFIED compensating action — rolls back an AI-initiated database change."""

import logging
from typing import Any

logger = logging.getLogger("tracemark.remediation.actions")


async def rollback_database_change(context: dict[str, Any]) -> dict[str, Any]:
    """Compensating action: roll back a database change made by AI.

    In production, this would execute a compensating SQL statement or restore
    from the write-ahead log. For the MVP, this simulates the rollback.
    """
    table = context.get("table", "unknown")
    record_id = context.get("record_id", "unknown")
    operation = context.get("operation", "UPDATE")
    previous_state = context.get("previous_state", {})

    logger.info(f"DB ROLLBACK: Rolling back {operation} on {table} record {record_id}")

    return {
        "action": "database_change_rolled_back",
        "table": table,
        "record_id": record_id,
        "operation": operation,
        "restored_state": previous_state,
        "rollback_status": "success",
        "message": f"Database {operation} on {table}.{record_id} rolled back",
    }
