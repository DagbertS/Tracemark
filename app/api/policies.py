"""Policies API — list, create, update, delete, and auto-suggest policy enforcement rules."""

from __future__ import annotations

from fastapi import APIRouter, Query
from pydantic import BaseModel
from typing import Any, Optional

router = APIRouter(prefix="/api/policies", tags=["policies"])

# Set by main.py at startup
policy_engine = None  # type: ignore
provenance_store = None  # type: ignore


class PolicyCreateRequest(BaseModel):
    """Request body for creating a new policy."""
    id: Optional[str] = None
    name: str
    type: str = "BOTH"  # PRE_CALL | POST_CALL | BOTH
    action: str = "BLOCK"  # BLOCK | TRANSFORM | ALLOW_AND_LOG | REMEDIATE
    enabled: bool = True
    policy_class: Optional[str] = None  # pii-detection | topic-blocklist | confidence-check
    config: dict[str, Any] = {}


class PolicyUpdateRequest(BaseModel):
    """Request body for updating an existing policy."""
    name: Optional[str] = None
    action: Optional[str] = None
    enabled: Optional[bool] = None
    config: Optional[dict[str, Any]] = None


class PolicyApprovalRequest(BaseModel):
    """Request body for approving/rejecting a pending policy."""
    action: str  # "approve" or "reject"


class PolicyRemediationTextRequest(BaseModel):
    """Request body for updating policy remediation text."""
    text: str


@router.get("")
async def list_policies():
    """List all active policies with their configurations."""
    return policy_engine.get_active_policies()


@router.post("")
async def create_policy(req: PolicyCreateRequest):
    """Create a new policy dynamically at runtime.

    The policy is immediately active upon creation. Use the enabled flag
    to create a policy in a disabled state for review.
    """
    policy_config = {
        "id": req.id,
        "name": req.name,
        "type": req.type,
        "action": req.action,
        "enabled": req.enabled,
        "config": req.config,
    }
    if req.policy_class:
        policy_config["policy_class"] = req.policy_class
    return policy_engine.add_policy(policy_config)


@router.put("/{policy_id}")
async def update_policy(policy_id: str, req: PolicyUpdateRequest):
    """Update an existing policy's configuration."""
    updates = {}
    if req.name is not None:
        updates["name"] = req.name
    if req.action is not None:
        updates["action"] = req.action
    if req.enabled is not None:
        updates["enabled"] = req.enabled
    if req.config is not None:
        updates["config"] = req.config
    return policy_engine.update_policy(policy_id, updates)


@router.delete("/{policy_id}")
async def delete_policy(policy_id: str):
    """Delete a policy by ID."""
    return policy_engine.delete_policy(policy_id)


@router.put("/{policy_id}/remediation-text")
async def update_policy_remediation_text(policy_id: str, req: PolicyRemediationTextRequest):
    """Update the remediation procedure text (rich HTML) for a policy."""
    success = policy_engine.set_policy_remediation_text(policy_id, req.text)
    if success:
        return {"status": "ok", "policy_id": policy_id, "message": "Remediation text updated"}
    return {"error": f"Policy '{policy_id}' not found", "status": "not_found"}


@router.post("/suggest")
async def suggest_policies(
    limit: int = Query(default=100, le=500, description="Number of historical entries to analyze"),
):
    """Analyze historical interceptions and suggest new policy rules.

    Examines patterns in past violations, blocked content, and warnings to
    recommend new policies. All suggestions are marked as 'pending_approval'
    and must be explicitly approved by a human before activation.
    """
    entries = await provenance_store.get_entries(limit=limit)
    suggestions = policy_engine.suggest_policies_from_history(entries)
    return {
        "suggestions": suggestions,
        "entries_analyzed": len(entries),
        "message": f"Generated {len(suggestions)} policy suggestion(s) from {len(entries)} historical entries. All require human approval.",
    }


@router.get("/pending")
async def list_pending_policies():
    """List all policy suggestions awaiting human approval."""
    return policy_engine.get_pending_policies()


@router.post("/pending/{policy_id}")
async def handle_pending_policy(policy_id: str, req: PolicyApprovalRequest):
    """Approve or reject a pending policy suggestion.

    This is the human-in-the-loop step: auto-suggested policies are never
    activated without explicit human approval.
    """
    if req.action == "approve":
        return policy_engine.approve_pending_policy(policy_id)
    elif req.action == "reject":
        return policy_engine.reject_pending_policy(policy_id)
    return {"error": "action must be 'approve' or 'reject'", "status": "invalid"}
