"""Tests for the Tracemark SAGA remediation engine."""

import pytest
import pytest_asyncio

from app.remediation import ActionRegistry, SAGAOrchestrator
from app.remediation.actions.email_action import retract_email
from app.remediation.actions.crm_action import restore_crm_record
from app.remediation.actions.notify_action import send_compliance_override


@pytest.fixture
def registry():
    r = ActionRegistry()
    r.register("EMAIL_SENT", "AI email sent", retract_email, notify_compliance=True)
    r.register("CRM_UPDATED", "AI CRM update", restore_crm_record, notify_compliance=False)
    r.register("NOTIFICATION_SENT", "AI notification", send_compliance_override, notify_compliance=True)
    return r


@pytest.fixture
def orchestrator(registry):
    return SAGAOrchestrator(registry=registry)


@pytest.mark.asyncio
async def test_email_compensation_executes(orchestrator):
    result = await orchestrator.execute_compensation(
        action_type="EMAIL_SENT",
        context={"recipient": "test@example.com", "subject": "Test"},
        reason="Policy violation",
    )
    assert result["status"] == "COMPLETED"
    assert result["action_type"] == "EMAIL_SENT"


@pytest.mark.asyncio
async def test_saga_log_written(orchestrator):
    await orchestrator.execute_compensation(
        action_type="EMAIL_SENT",
        context={"recipient": "test@example.com"},
        reason="Test",
    )
    log = orchestrator.get_saga_log()
    assert len(log) == 1
    assert log[0]["status"] == "COMPLETED"
    assert log[0]["saga_id"] is not None


@pytest.mark.asyncio
async def test_unknown_action_handled(orchestrator):
    result = await orchestrator.execute_compensation(
        action_type="UNKNOWN_ACTION",
        context={},
        reason="Test unknown",
    )
    assert result["status"] == "FAILED"
    assert "Unknown action type" in result["error"]


@pytest.mark.asyncio
async def test_crm_compensation(orchestrator):
    result = await orchestrator.execute_compensation(
        action_type="CRM_UPDATED",
        context={"record_id": "CRM-001", "field_name": "email", "previous_value": "old@test.com"},
        reason="AI made unauthorized CRM change",
    )
    assert result["status"] == "COMPLETED"


@pytest.mark.asyncio
async def test_registry_list(registry):
    actions = registry.list_actions()
    assert len(actions) == 3
    names = [a["action_type"] for a in actions]
    assert "EMAIL_SENT" in names
    assert "CRM_UPDATED" in names
    assert "NOTIFICATION_SENT" in names


@pytest.mark.asyncio
async def test_compliance_notification_flag(orchestrator):
    result = await orchestrator.execute_compensation(
        action_type="EMAIL_SENT",
        context={},
        reason="Test compliance",
    )
    assert result["status"] == "COMPLETED"
    assert result.get("compliance_notified") is True
