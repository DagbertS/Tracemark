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
) -> list[dict[str, Any]]:
    """List provenance entries with optional filtering."""
    return await provenance_store.get_entries(
        limit=limit, offset=offset, verdict=verdict, caller_id=caller_id
    )


@router.get("/verify")
async def verify_chain() -> dict[str, Any]:
    """Verify the integrity of the entire provenance chain."""
    return await provenance_store.verify_chain()


@router.get("/stats")
async def provenance_stats() -> dict[str, Any]:
    """Get aggregate statistics from the provenance trail."""
    return await provenance_store.get_stats()


@router.get("/{entry_id}")
async def get_provenance_entry(entry_id: str) -> dict[str, Any]:
    """Get a single provenance entry by ID."""
    entry = await provenance_store.get_entry(entry_id)
    if entry is None:
        return {"error": "Entry not found"}
    return entry
