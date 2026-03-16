"""Enterprise Connector Framework — Slack, Email, Webhook integrations."""

from .base import BaseConnector
from .slack import SlackConnector
from .email import EmailConnector
from .webhook import WebhookConnector
from .registry import ConnectorRegistry

__all__ = [
    "BaseConnector", "SlackConnector", "EmailConnector",
    "WebhookConnector", "ConnectorRegistry",
]
