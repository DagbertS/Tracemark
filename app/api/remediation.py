"""Remediation API — trigger manual compensating actions, WYSIWYG editing, and auto-generation."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime

from fastapi import APIRouter
from pydantic import BaseModel
from typing import Any, Dict

router = APIRouter(prefix="/api", tags=["remediation"])

# Set by main.py at startup
saga_orchestrator = None  # type: ignore
action_registry = None  # type: ignore
provenance_store = None  # type: ignore


class RemediationRequest(BaseModel):
    action_type: str
    context: Dict[str, Any] = {}
    reason: str = "Manual remediation triggered"


class RemediationTextRequest(BaseModel):
    text: str


@router.post("/remediate")
async def trigger_remediation(req: RemediationRequest) -> dict[str, Any]:
    """Trigger a manual compensating action for a registered action type."""
    result = await saga_orchestrator.execute_compensation(
        action_type=req.action_type,
        context=req.context,
        reason=req.reason,
    )
    return result


@router.get("/remediation/log")
async def get_saga_log(limit: int = 50) -> list[dict[str, Any]]:
    """View the SAGA execution log of all compensating actions."""
    return saga_orchestrator.get_saga_log(limit=limit)


@router.get("/remediation/registry")
async def get_action_registry() -> list[dict[str, Any]]:
    """List all registered action types and their compensating actions."""
    return action_registry.list_actions()


@router.put("/remediation/registry/{action_type}/text")
async def update_remediation_text(action_type: str, req: RemediationTextRequest) -> dict[str, Any]:
    """Update the remediation procedure text (rich HTML) for an action type."""
    success = action_registry.set_remediation_text(action_type, req.text)
    if success:
        return {"status": "ok", "action_type": action_type, "message": "Remediation text updated"}
    return {"status": "error", "message": f"Unknown action type: {action_type}"}


@router.post("/remediation/auto-generate")
async def auto_generate_remediations() -> dict[str, Any]:
    """Auto-generate remediation procedures from WARNING provenance entries."""
    entries = await provenance_store.get_entries(verdict="WARNING", limit=500)

    if not entries:
        return {"generated": [], "message": "No WARNING entries found"}

    # Group warnings by policy
    policy_groups: dict[str, list] = defaultdict(list)
    for entry in entries:
        for verdict in entry.get("policy_verdicts", []):
            if verdict.get("result") == "WARNING":
                policy_groups[verdict.get("policy_name", "Unknown")].append({
                    "entry_id": entry["id"],
                    "caller_id": entry.get("caller_id", ""),
                    "timestamp": entry.get("timestamp", ""),
                    "matched_rule": verdict.get("matched_rule", ""),
                    "action_taken": verdict.get("action_taken", ""),
                })

    generated = []
    for policy_name, warnings in policy_groups.items():
        callers = list(set(w["caller_id"] for w in warnings))
        sample_rules = list(set(w["matched_rule"] for w in warnings if w["matched_rule"]))
        timestamps = sorted(w["timestamp"] for w in warnings if w["timestamp"])

        remediation_html = f"""<h3>Auto-Remediation: {policy_name}</h3>
<p><strong>Generated:</strong> {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}</p>
<p><strong>Based on:</strong> {len(warnings)} warning(s) from {len(callers)} caller(s)</p>
<p><strong>Date range:</strong> {timestamps[0][:10] if timestamps else 'N/A'} to {timestamps[-1][:10] if timestamps else 'N/A'}</p>
<h4>Matched Rules</h4>
<ul>{''.join(f'<li>{r}</li>' for r in sample_rules)}</ul>
<h4>Affected Callers</h4>
<ul>{''.join(f'<li>{c}</li>' for c in callers)}</ul>
<h4>Recommended Steps</h4>
<ol>
  <li>Review all flagged entries in the provenance log filtered by WARNING verdict</li>
  <li>Assess whether the warning conditions represent genuine risk</li>
  <li>If risk is confirmed: escalate to BLOCK action and notify compliance</li>
  <li>If false positive: adjust policy sensitivity or add exceptions</li>
  <li>Document the decision and update the policy configuration</li>
</ol>"""

        generated.append({
            "policy_name": policy_name,
            "warning_count": len(warnings),
            "callers": callers,
            "remediation_html": remediation_html,
            "sample_entry_ids": [w["entry_id"] for w in warnings[:5]],
        })

    return {
        "generated": generated,
        "total_warnings_analyzed": len(entries),
        "message": f"Generated {len(generated)} remediation(s) from {len(entries)} warning entries",
    }
