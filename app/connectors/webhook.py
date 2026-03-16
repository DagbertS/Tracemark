"""Generic HTTP webhook connector — the enterprise integration escape hatch.

Connects to any system (SAP, Salesforce, ServiceNow, etc.) via HTTP webhooks.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import httpx

from .base import BaseConnector

logger = logging.getLogger("tracemark.connectors.webhook")


class WebhookConnector(BaseConnector):
    """Generic HTTP webhook for enterprise system integration."""

    connector_type = "webhook"

    async def configure(self) -> bool:
        url = self.config.get("url", "")
        if not url or not url.startswith("http"):
            logger.error(f"Webhook connector {self.connector_id}: invalid url")
            return False
        method = self.config.get("method", "POST").upper()
        if method not in ("POST", "PUT", "PATCH"):
            logger.error(f"Webhook connector {self.connector_id}: unsupported method '{method}'")
            return False
        self.status = "active"
        return True

    async def validate(self) -> dict:
        """Test webhook connectivity with a HEAD/GET request."""
        url = self.config.get("url", "")
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.head(url, timeout=10.0)
                if resp.status_code < 500:
                    return {"success": True, "message": f"Webhook reachable (status {resp.status_code})"}
                return {"success": False, "message": f"Webhook returned {resp.status_code}"}
        except Exception as e:
            return {"success": False, "message": f"Webhook connection failed: {e}"}

    async def execute(self, payload: dict) -> dict:
        """Send HTTP request to the configured webhook."""
        url = self.config.get("url", "")
        method = self.config.get("method", "POST").upper()
        custom_headers = dict(self.config.get("headers", {}))

        # Add Tracemark event header
        custom_headers["X-Tracemark-Event"] = payload.get("event_type", "policy_violation")
        custom_headers.setdefault("Content-Type", "application/json")

        # Apply auth
        auth_type = self.config.get("auth_type", "none")
        if auth_type == "bearer":
            custom_headers["Authorization"] = f"Bearer {self.config.get('auth_token', '')}"
        elif auth_type == "basic":
            import base64
            creds = base64.b64encode(
                f"{self.config.get('auth_user', '')}:{self.config.get('auth_pass', '')}".encode()
            ).decode()
            custom_headers["Authorization"] = f"Basic {creds}"

        # Apply body template
        body_template = self.config.get("body_template")
        if body_template:
            body_str = json.dumps(body_template)
            for key, value in payload.items():
                body_str = body_str.replace("{{" + key + "}}", str(value))
            body = json.loads(body_str)
        else:
            body = payload

        async with httpx.AsyncClient() as client:
            resp = await client.request(
                method, url,
                json=body,
                headers=custom_headers,
                timeout=30.0,
            )
            resp.raise_for_status()

        logger.info(f"Webhook {method} {url} completed with status {resp.status_code}")
        return {
            "action": "webhook_executed",
            "url": url,
            "method": method,
            "status_code": resp.status_code,
            "status": "success",
        }

    async def rollback(self, execution_id: str) -> dict:
        """Attempt rollback via configured rollback_url if available."""
        rollback_url = self.config.get("rollback_url")
        if not rollback_url:
            return {
                "action": "rollback_not_available",
                "reason": "No rollback_url configured",
                "execution_id": execution_id,
            }

        try:
            async with httpx.AsyncClient() as client:
                resp = await client.post(
                    rollback_url,
                    json={"execution_id": execution_id, "action": "rollback"},
                    timeout=30.0,
                )
                return {
                    "action": "webhook_rollback",
                    "url": rollback_url,
                    "status_code": resp.status_code,
                    "status": "success" if resp.status_code < 400 else "failed",
                }
        except Exception as e:
            return {"action": "rollback_failed", "error": str(e), "execution_id": execution_id}
