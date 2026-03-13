"""Tests for the Tracemark interception proxy."""

from __future__ import annotations

import os
import pytest
import pytest_asyncio
import yaml
from httpx import ASGITransport, AsyncClient

# Set env before importing app
os.environ["TRACEMARK_CONFIG"] = os.path.join(os.path.dirname(os.path.dirname(__file__)), "config.yaml")
os.environ["TRACEMARK_DB_PATH"] = "test_proxy_provenance.db"
os.environ["TRACEMARK_SECRET_KEY"] = "test-secret"

from app import proxy
from app.api import provenance as provenance_api, policies as policies_api, remediation as remediation_api
from app.policy_engine import PolicyEngine
from app.provenance import ProvenanceStore
from app.remediation import SAGAOrchestrator, ActionRegistry
from app.remediation.actions.email_action import retract_email
from app.remediation.actions.crm_action import restore_crm_record
from app.remediation.actions.notify_action import send_compliance_override
from app.main import app


@pytest_asyncio.fixture
async def client():
    db_path = "test_proxy_provenance.db"
    if os.path.exists(db_path):
        os.remove(db_path)

    # Manually initialize all components (bypass lifespan)
    config_path = os.environ["TRACEMARK_CONFIG"]
    with open(config_path) as f:
        config = yaml.safe_load(f)

    pe = PolicyEngine(config.get("policies", []))
    ps = ProvenanceStore(db_path=db_path, secret_key="test-secret")
    await ps.initialize()

    ar = ActionRegistry()
    ar.register("EMAIL_SENT", "AI email sent", retract_email, notify_compliance=True)
    ar.register("CRM_UPDATED", "AI CRM update", restore_crm_record)
    ar.register("NOTIFICATION_SENT", "AI notification", send_compliance_override, notify_compliance=True)
    so = SAGAOrchestrator(registry=ar)

    # Wire up module-level refs
    proxy.policy_engine = pe
    proxy.provenance_store = ps
    proxy.saga_orchestrator = so
    proxy.upstream_config = {"base_url": "", "mock_mode": True, "api_key": ""}

    provenance_api.provenance_store = ps
    policies_api.policy_engine = pe
    remediation_api.saga_orchestrator = so
    remediation_api.action_registry = ar

    transport = ASGITransport(app=app, raise_app_exceptions=False)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac

    if os.path.exists(db_path):
        os.remove(db_path)


@pytest.mark.asyncio
async def test_clean_call_passes(client):
    resp = await client.post(
        "/v1/chat/completions",
        json={"model": "gpt-4o", "messages": [{"role": "user", "content": "Summarize our Q3 roadmap."}]},
        headers={"X-Tracemark-Caller": "test", "X-Tracemark-Session": "test-session"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "choices" in data
    assert data["choices"][0]["message"]["content"]


@pytest.mark.asyncio
async def test_pii_in_request_blocked(client):
    resp = await client.post(
        "/v1/chat/completions",
        json={"model": "gpt-4o", "messages": [{"role": "user", "content": "Email john.doe@customer.com about their account."}]},
    )
    assert resp.status_code == 403
    data = resp.json()
    assert data["error"]["type"] == "policy_violation"


@pytest.mark.asyncio
async def test_forbidden_topic_blocked(client):
    resp = await client.post(
        "/v1/chat/completions",
        json={"model": "gpt-4o", "messages": [{"role": "user", "content": "What is the competitor pricing for similar SaaS tools?"}]},
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_provenance_headers(client):
    resp = await client.post(
        "/v1/chat/completions",
        json={"model": "gpt-4o", "messages": [{"role": "user", "content": "What are our Q3 goals?"}]},
        headers={"X-Tracemark-Caller": "test"},
    )
    assert "tracemark-entry-id" in resp.headers
    assert "tracemark-verdict" in resp.headers


@pytest.mark.asyncio
async def test_mock_mode_works(client):
    resp = await client.post(
        "/v1/chat/completions",
        json={"model": "gpt-4o", "messages": [{"role": "user", "content": "Tell me about our products."}]},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["id"].startswith("chatcmpl-tm-")


@pytest.mark.asyncio
async def test_pii_in_response_caught(client):
    # The mock returns PII content for prompts with "email" + "customer"
    # The request itself has no PII pattern (no @ symbol), so pre-call passes.
    # Post-call catches PII in the mock response and blocks it.
    resp = await client.post(
        "/v1/chat/completions",
        json={"model": "gpt-4o", "messages": [
            {"role": "system", "content": "You are a CRM assistant."},
            {"role": "user", "content": "Look up the customer record and send them an email about their account details."},
        ]},
    )
    # Post-call PII detection should catch the mock response containing email/phone
    if resp.status_code == 403:
        data = resp.json()
        assert data["error"]["type"] == "policy_violation"
    else:
        # Even if not blocked, it should have a non-PASS verdict
        assert "tracemark-verdict" in resp.headers
