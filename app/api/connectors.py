"""Connectors API — CRUD and execution endpoints for enterprise connectors."""

from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Query
from pydantic import BaseModel

logger = logging.getLogger("tracemark.api.connectors")

router = APIRouter(prefix="/api/connectors", tags=["connectors"])

# Module-level reference set by main.py
connector_registry = None  # type: ignore


class ConnectorCreateRequest(BaseModel):
    tenant_id: str
    type: str  # slack, email, webhook
    name: str
    config: dict


class ConnectorExecuteRequest(BaseModel):
    payload: dict


@router.get("")
async def list_connectors(tenant_id: Optional[str] = Query(default=None)):
    """List all active connectors, optionally filtered by tenant."""
    connectors = connector_registry.list_connectors(tenant_id=tenant_id)
    return {"connectors": connectors, "total": len(connectors)}


@router.post("")
async def create_connector(req: ConnectorCreateRequest):
    """Create a new connector."""
    result = await connector_registry.register(
        tenant_id=req.tenant_id,
        connector_type=req.type,
        name=req.name,
        config=req.config,
    )
    if "error" in result:
        from fastapi.responses import JSONResponse
        return JSONResponse(status_code=400, content=result)
    return result


@router.post("/{connector_id}/test")
async def test_connector(connector_id: str):
    """Test connector connectivity."""
    result = await connector_registry.validate(connector_id)
    return result


@router.post("/{connector_id}/execute")
async def execute_connector(connector_id: str, req: ConnectorExecuteRequest):
    """Execute a connector with the given payload."""
    result = await connector_registry.execute(connector_id, req.payload)
    return result


@router.delete("/{connector_id}")
async def delete_connector(connector_id: str):
    """Remove a connector."""
    result = await connector_registry.remove(connector_id)
    if "error" in result:
        from fastapi.responses import JSONResponse
        return JSONResponse(status_code=404, content=result)
    return result


@router.get("/types")
async def connector_types():
    """List available connector types."""
    return {
        "types": [
            {
                "type": "slack",
                "name": "Slack Webhook",
                "description": "Send violation alerts to Slack channels",
                "required_config": ["webhook_url"],
                "optional_config": ["channel", "username", "message_template"],
            },
            {
                "type": "email",
                "name": "Email (SMTP)",
                "description": "Send compliance notifications via email",
                "required_config": ["smtp_host", "from_address"],
                "optional_config": ["smtp_port", "smtp_user", "smtp_pass", "to_address", "subject_template", "body_template"],
            },
            {
                "type": "webhook",
                "name": "Generic HTTP Webhook",
                "description": "Connect to any enterprise system via HTTP",
                "required_config": ["url"],
                "optional_config": ["method", "headers", "auth_type", "auth_token", "body_template", "rollback_url"],
            },
        ]
    }
