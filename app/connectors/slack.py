"""Slack webhook connector — sends violation alerts to Slack channels."""

from __future__ import annotations

import logging
from typing import Any

import httpx

from .base import BaseConnector

logger = logging.getLogger("tracemark.connectors.slack")


class SlackConnector(BaseConnector):
    """Sends formatted messages to Slack via incoming webhooks."""

    connector_type = "slack"

    async def configure(self) -> bool:
        webhook_url = self.config.get("webhook_url", "")
        if not webhook_url or not webhook_url.startswith("http"):
            logger.error(f"Slack connector {self.connector_id}: invalid webhook_url")
            return False
        self.status = "active"
        return True

    async def validate(self) -> dict:
        """Send a test message to verify webhook connectivity."""
        webhook_url = self.config.get("webhook_url", "")
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.post(
                    webhook_url,
                    json={"text": ":white_check_mark: Tracemark connectivity test — webhook is working!"},
                    timeout=10.0,
                )
                if resp.status_code == 200:
                    return {"success": True, "message": "Slack webhook validated successfully"}
                return {"success": False, "message": f"Slack returned status {resp.status_code}"}
        except Exception as e:
            return {"success": False, "message": f"Slack connection failed: {e}"}

    async def execute(self, payload: dict) -> dict:
        """Send a formatted violation alert to Slack."""
        webhook_url = self.config.get("webhook_url", "")
        channel = self.config.get("channel", "#tracemark-alerts")
        username = self.config.get("username", "Tracemark AI Governance")

        # Build Slack message from payload
        violation_type = payload.get("violation", "Policy Violation")
        caller = payload.get("caller", "unknown")
        policy = payload.get("policy", "unknown")
        entry_id = payload.get("entry_id", "")
        timestamp = payload.get("timestamp", "")
        base_url = payload.get("base_url", "https://tracemark-production.up.railway.app")

        message = {
            "channel": channel,
            "username": username,
            "icon_emoji": ":shield:",
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": f":rotating_light: {violation_type}",
                        "emoji": True,
                    },
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*Caller:*\n{caller}"},
                        {"type": "mrkdwn", "text": f"*Policy:*\n{policy}"},
                        {"type": "mrkdwn", "text": f"*Time:*\n{timestamp}"},
                        {"type": "mrkdwn", "text": f"*Entry ID:*\n`{entry_id[:12]}...`"},
                    ],
                },
                {
                    "type": "actions",
                    "elements": [
                        {
                            "type": "button",
                            "text": {"type": "plain_text", "text": "View in Dashboard"},
                            "url": f"{base_url}/#provenance/{entry_id}",
                        },
                    ],
                },
            ],
        }

        # Apply custom message template if provided
        template = self.config.get("message_template")
        if template:
            message = {"channel": channel, "username": username, "text": template.format(**payload)}

        async with httpx.AsyncClient() as client:
            resp = await client.post(webhook_url, json=message, timeout=10.0)
            resp.raise_for_status()

        logger.info(f"Slack notification sent to {channel} for entry {entry_id}")
        return {"action": "slack_notification_sent", "channel": channel, "status": "success"}

    async def rollback(self, execution_id: str) -> dict:
        """Slack webhooks are fire-and-forget — rollback not possible."""
        return {
            "action": "rollback_not_available",
            "reason": "Slack webhook messages cannot be retracted",
            "execution_id": execution_id,
        }
