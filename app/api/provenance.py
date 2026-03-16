"""Provenance API — query and verify the tamper-proof audit trail."""

from __future__ import annotations

from fastapi import APIRouter, Query
from typing import Any, Optional

router = APIRouter(prefix="/api/provenance", tags=["provenance"])

# Set by main.py at startup
provenance_store = None  # type: ignore


@router.get("")
async def list_provenance(
    limit: int = Query(default=50, le=500),
    offset: int = Query(default=0, ge=0),
    verdict: Optional[str] = Query(default=None),
    caller_id: Optional[str] = Query(default=None),
    tenant_id: Optional[str] = Query(default=None),
) -> list:
    """List provenance entries with optional filtering."""
    return await provenance_store.get_entries(
        limit=limit, offset=offset, verdict=verdict,
        caller_id=caller_id, tenant_id=tenant_id,
    )


@router.get("/verify")
async def verify_chain(
    tenant: Optional[str] = Query(default=None),
) -> dict:
    """Verify the integrity of the provenance chain.

    Returns the chain verification result including:
    - status: INTACT, TAMPERED, or EMPTY
    - total_entries: number of entries verified
    - Details about any tampered entries
    """
    result = await provenance_store.verify_chain()

    # Map to the standardized response format
    if result.get("entries_verified", 0) == 0:
        status = "EMPTY"
    elif result.get("intact", False):
        status = "INTACT"
    else:
        status = "TAMPERED"

    return {
        "status": status,
        "intact": result.get("intact", True),
        "total_entries": result.get("total_entries", result.get("entries_verified", 0)),
        "verified_entries": result.get("entries_verified", 0),
        "first_entry_id": result.get("first_entry_id"),
        "last_entry_id": result.get("last_entry_id"),
        "first_entry_timestamp": result.get("first_entry_timestamp"),
        "latest_entry_timestamp": result.get("latest_entry_timestamp"),
        "last_verified_at": result.get("last_verified_at"),
        "tampered_at_entry": result.get("tampered_entry_id"),
        "message": result.get("message", ""),
        # Keep backward compatibility
        "entries_verified": result.get("entries_verified", 0),
    }


@router.get("/stats")
async def provenance_stats() -> dict:
    """Get aggregate statistics from the provenance trail."""
    return await provenance_store.get_stats()


@router.get("/{entry_id}")
async def get_provenance_entry(entry_id: str) -> dict:
    """Get a single provenance entry by ID."""
    entry = await provenance_store.get_entry(entry_id)
    if entry is None:
        return {"error": "Entry not found"}
    return entry
