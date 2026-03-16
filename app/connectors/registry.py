"""Connector Registry — manages connector lifecycle and persistence."""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

import aiosqlite

from .base import BaseConnector
from .slack import SlackConnector
from .email import EmailConnector
from .webhook import WebhookConnector

logger = logging.getLogger("tracemark.connectors.registry")

CONNECTOR_CLASSES = {
    "slack": SlackConnector,
    "email": EmailConnector,
    "webhook": WebhookConnector,
}

CONNECTOR_SCHEMA = """
CREATE TABLE IF NOT EXISTS connectors (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    connector_type TEXT NOT NULL,
    name TEXT NOT NULL,
    config TEXT NOT NULL,
    status TEXT DEFAULT 'active',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_connectors_tenant ON connectors(tenant_id);
"""

CONNECTOR_MIGRATION = [
    "ALTER TABLE connectors ADD COLUMN name TEXT DEFAULT 'Unnamed'",
]


class ConnectorRegistry:
    """Manages connector instances with SQLite persistence."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._connectors: dict = {}  # connector_id -> BaseConnector instance

    async def initialize(self):
        """Create connectors table and load existing configurations."""
        async with aiosqlite.connect(self.db_path) as db:
            await db.executescript(CONNECTOR_SCHEMA)
            await db.commit()
            for migration in CONNECTOR_MIGRATION:
                try:
                    await db.execute(migration)
                    await db.commit()
                except Exception:
                    pass

            # Load existing connectors
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("SELECT * FROM connectors WHERE status = 'active'")
            rows = await cursor.fetchall()
            for row in rows:
                row_dict = dict(row)
                try:
                    config = json.loads(row_dict["config"])
                    connector = self._create_instance(
                        connector_id=row_dict["id"],
                        tenant_id=row_dict["tenant_id"],
                        connector_type=row_dict["connector_type"],
                        name=row_dict.get("name", "Unnamed"),
                        config=config,
                    )
                    if connector:
                        await connector.configure()
                        self._connectors[connector.connector_id] = connector
                except Exception as e:
                    logger.error(f"Failed to load connector {row_dict['id']}: {e}")

        logger.info(f"ConnectorRegistry initialized with {len(self._connectors)} connectors")

    def _create_instance(self, connector_id: str, tenant_id: str,
                         connector_type: str, name: str, config: dict) -> Optional[BaseConnector]:
        cls = CONNECTOR_CLASSES.get(connector_type)
        if not cls:
            logger.error(f"Unknown connector type: {connector_type}")
            return None
        return cls(
            connector_id=connector_id,
            tenant_id=tenant_id,
            name=name,
            config=config,
        )

    async def register(self, tenant_id: str, connector_type: str,
                       name: str, config: dict) -> dict:
        """Create and persist a new connector."""
        connector_id = f"conn-{uuid.uuid4().hex[:8]}"
        now = datetime.now(timezone.utc).isoformat()

        connector = self._create_instance(connector_id, tenant_id, connector_type, name, config)
        if not connector:
            return {"error": f"Unknown connector type: {connector_type}", "status": "failed"}

        configured = await connector.configure()
        if not configured:
            return {"error": "Connector configuration invalid", "status": "failed"}

        # Persist to DB
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                "INSERT INTO connectors (id, tenant_id, connector_type, name, config, status, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (connector_id, tenant_id, connector_type, name, json.dumps(config), "active", now, now),
            )
            await db.commit()

        self._connectors[connector_id] = connector
        logger.info(f"Connector registered: {connector_id} ({connector_type}) for tenant {tenant_id}")
        return {"status": "created", "connector": connector.to_dict()}

    async def execute(self, connector_id: str, payload: dict) -> dict:
        """Execute a connector with retry."""
        connector = self._connectors.get(connector_id)
        if not connector:
            return {"error": f"Connector {connector_id} not found", "status": "failed"}
        return await connector.execute_with_retry(payload)

    async def validate(self, connector_id: str) -> dict:
        """Test connector connectivity."""
        connector = self._connectors.get(connector_id)
        if not connector:
            return {"error": f"Connector {connector_id} not found", "status": "failed"}
        return await connector.validate()

    async def remove(self, connector_id: str) -> dict:
        """Deactivate and remove a connector."""
        if connector_id not in self._connectors:
            return {"error": f"Connector {connector_id} not found", "status": "failed"}

        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                "UPDATE connectors SET status = 'deleted', updated_at = ? WHERE id = ?",
                (datetime.now(timezone.utc).isoformat(), connector_id),
            )
            await db.commit()

        del self._connectors[connector_id]
        return {"status": "deleted", "connector_id": connector_id}

    def list_connectors(self, tenant_id: Optional[str] = None) -> list:
        """List all active connectors, optionally filtered by tenant."""
        connectors = list(self._connectors.values())
        if tenant_id:
            connectors = [c for c in connectors if c.tenant_id == tenant_id]
        return [c.to_dict() for c in connectors]

    def get_connector(self, connector_id: str) -> Optional[BaseConnector]:
        return self._connectors.get(connector_id)

    def get_connectors_for_tenant(self, tenant_id: str) -> list:
        """Get all connectors for a specific tenant."""
        return [c for c in self._connectors.values() if c.tenant_id == tenant_id]
