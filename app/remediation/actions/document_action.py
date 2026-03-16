"""DOCUMENT_SHARED compensating action — revokes access to an AI-shared document."""

import logging
from typing import Any

logger = logging.getLogger("tracemark.remediation.actions")


async def revoke_document_access(context: dict[str, Any]) -> dict[str, Any]:
    """Compensating action: revoke access to a document shared by AI.

    In production, this would call the document management API to revoke sharing
    permissions. For the MVP, this simulates the revocation.
    """
    document_id = context.get("document_id", "unknown")
    shared_with = context.get("shared_with", "unknown")
    platform = context.get("platform", "internal")

    logger.info(f"REVOKE DOC ACCESS: Revoking access to {document_id} from {shared_with}")

    return {
        "action": "document_access_revoked",
        "document_id": document_id,
        "shared_with": shared_with,
        "platform": platform,
        "revocation_status": "success",
        "message": f"Access to document {document_id} revoked from {shared_with}",
    }
