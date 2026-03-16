"""Base connector class for enterprise integrations.

All connectors implement: configure(), validate(), execute(), rollback().
Failed executions retry 3 times with exponential backoff.
"""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Optional

logger = logging.getLogger("tracemark.connectors")


class BaseConnector(ABC):
    """Abstract base class for all enterprise connectors."""

    connector_type: str = "base"

    def __init__(self, connector_id: str, tenant_id: str, name: str, config: dict):
        self.connector_id = connector_id
        self.tenant_id = tenant_id
        self.name = name
        self.config = config
        self.status = "configured"
        self.created_at = datetime.now(timezone.utc).isoformat()
        self.last_executed_at: Optional[str] = None

    @abstractmethod
    async def configure(self) -> bool:
        """Validate configuration and set up the connector. Returns True if valid."""
        ...

    @abstractmethod
    async def validate(self) -> dict:
        """Test connectivity. Returns status dict with 'success' and 'message'."""
        ...

    @abstractmethod
    async def execute(self, payload: dict) -> dict:
        """Execute the connector action. Returns result dict."""
        ...

    @abstractmethod
    async def rollback(self, execution_id: str) -> dict:
        """Attempt to reverse the action. Returns result dict."""
        ...

    async def execute_with_retry(self, payload: dict, max_retries: int = 3) -> dict:
        """Execute with exponential backoff retry."""
        last_error = None
        for attempt in range(max_retries):
            try:
                result = await self.execute(payload)
                self.last_executed_at = datetime.now(timezone.utc).isoformat()
                return {
                    "status": "COMPLETED",
                    "attempt": attempt + 1,
                    "result": result,
                    "connector_id": self.connector_id,
                    "connector_type": self.connector_type,
                    "timestamp": self.last_executed_at,
                }
            except Exception as e:
                last_error = str(e)
                if attempt < max_retries - 1:
                    delay = 2 ** attempt  # 1s, 2s, 4s
                    logger.warning(
                        f"Connector {self.connector_id} attempt {attempt + 1} failed: {e}. "
                        f"Retrying in {delay}s..."
                    )
                    await asyncio.sleep(delay)

        return {
            "status": "FAILED",
            "attempts": max_retries,
            "error": last_error,
            "connector_id": self.connector_id,
            "connector_type": self.connector_type,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    def to_dict(self) -> dict:
        return {
            "id": self.connector_id,
            "tenant_id": self.tenant_id,
            "name": self.name,
            "type": self.connector_type,
            "status": self.status,
            "config": {k: v for k, v in self.config.items() if k not in ("smtp_pass", "auth_token", "api_key")},
            "created_at": self.created_at,
            "last_executed_at": self.last_executed_at,
        }
