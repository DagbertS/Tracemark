"""Provenance Store — SQLite-backed, append-only, HMAC-chained audit trail.

Upgrade path: the HMAC chain can be extended to a Merkle tree structure for
distributed verification without changing the storage interface.
"""

from __future__ import annotations

import json
import logging
import aiosqlite
from typing import Any

from .models import ProvenanceEntry

logger = logging.getLogger("tracemark.provenance")

SCHEMA = """
CREATE TABLE IF NOT EXISTS provenance (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    session_id TEXT,
    caller_id TEXT,
    upstream_model TEXT,
    request_hash TEXT,
    response_hash TEXT,
    policy_verdicts TEXT,
    overall_verdict TEXT,
    remediation_id TEXT,
    latency_ms INTEGER,
    previous_entry_hash TEXT,
    entry_hash TEXT NOT NULL,
    -- Enriched fields: token usage & cost
    prompt_tokens INTEGER DEFAULT 0,
    completion_tokens INTEGER DEFAULT 0,
    total_tokens INTEGER DEFAULT 0,
    estimated_cost_usd REAL DEFAULT 0.0,
    -- Full request/response content (stored in DB only, never logged to stdout)
    request_body TEXT DEFAULT '',
    response_body TEXT DEFAULT '',
    system_prompt TEXT DEFAULT '',
    -- Model invocation parameters
    temperature REAL,
    max_tokens INTEGER,
    top_p REAL,
    frequency_penalty REAL,
    presence_penalty REAL,
    stop_sequences TEXT DEFAULT '[]',
    -- Tool / function call tracking
    tool_calls TEXT DEFAULT '[]',
    functions_available TEXT DEFAULT '[]',
    -- Model lineage / training data information
    model_info TEXT DEFAULT '{}',
    -- Finish reason
    finish_reason TEXT DEFAULT '',
    -- Request origin metadata
    request_ip TEXT DEFAULT '',
    user_agent TEXT DEFAULT '',
    -- System fingerprint, model routing & log probabilities
    system_fingerprint TEXT DEFAULT '',
    model_routing TEXT DEFAULT '{}',
    logprobs TEXT DEFAULT '{}',
    -- Tenant and sanitization
    tenant_id TEXT DEFAULT '',
    entities_masked TEXT DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_provenance_timestamp ON provenance(timestamp);
CREATE INDEX IF NOT EXISTS idx_provenance_verdict ON provenance(overall_verdict);
CREATE INDEX IF NOT EXISTS idx_provenance_caller ON provenance(caller_id);
CREATE INDEX IF NOT EXISTS idx_provenance_model ON provenance(upstream_model);
CREATE INDEX IF NOT EXISTS idx_provenance_tenant ON provenance(tenant_id);
"""

# Migration to add new columns to existing databases
MIGRATIONS = [
    "ALTER TABLE provenance ADD COLUMN prompt_tokens INTEGER DEFAULT 0",
    "ALTER TABLE provenance ADD COLUMN completion_tokens INTEGER DEFAULT 0",
    "ALTER TABLE provenance ADD COLUMN total_tokens INTEGER DEFAULT 0",
    "ALTER TABLE provenance ADD COLUMN estimated_cost_usd REAL DEFAULT 0.0",
    "ALTER TABLE provenance ADD COLUMN request_body TEXT DEFAULT ''",
    "ALTER TABLE provenance ADD COLUMN response_body TEXT DEFAULT ''",
    "ALTER TABLE provenance ADD COLUMN system_prompt TEXT DEFAULT ''",
    "ALTER TABLE provenance ADD COLUMN temperature REAL",
    "ALTER TABLE provenance ADD COLUMN max_tokens INTEGER",
    "ALTER TABLE provenance ADD COLUMN top_p REAL",
    "ALTER TABLE provenance ADD COLUMN frequency_penalty REAL",
    "ALTER TABLE provenance ADD COLUMN presence_penalty REAL",
    "ALTER TABLE provenance ADD COLUMN stop_sequences TEXT DEFAULT '[]'",
    "ALTER TABLE provenance ADD COLUMN tool_calls TEXT DEFAULT '[]'",
    "ALTER TABLE provenance ADD COLUMN functions_available TEXT DEFAULT '[]'",
    "ALTER TABLE provenance ADD COLUMN model_info TEXT DEFAULT '{}'",
    "ALTER TABLE provenance ADD COLUMN finish_reason TEXT DEFAULT ''",
    "ALTER TABLE provenance ADD COLUMN request_ip TEXT DEFAULT ''",
    "ALTER TABLE provenance ADD COLUMN user_agent TEXT DEFAULT ''",
    "ALTER TABLE provenance ADD COLUMN system_fingerprint TEXT DEFAULT ''",
    "ALTER TABLE provenance ADD COLUMN model_routing TEXT DEFAULT '{}'",
    "ALTER TABLE provenance ADD COLUMN logprobs TEXT DEFAULT '{}'",
    "ALTER TABLE provenance ADD COLUMN tenant_id TEXT DEFAULT ''",
    "ALTER TABLE provenance ADD COLUMN entities_masked TEXT DEFAULT '{}'",
]


class ProvenanceStore:
    """Append-only provenance store with HMAC-SHA256 chain integrity."""

    def __init__(self, db_path: str, secret_key: str):
        self.db_path = db_path
        self.secret_key = secret_key
        self._last_entry_hash: str = ""

    async def initialize(self):
        async with aiosqlite.connect(self.db_path) as db:
            await db.executescript(SCHEMA)
            await db.commit()
            # Run migrations for existing databases (add new columns if missing)
            for migration in MIGRATIONS:
                try:
                    await db.execute(migration)
                    await db.commit()
                except Exception:
                    pass  # Column already exists — safe to skip
            # Load the last entry hash to continue the chain
            cursor = await db.execute(
                "SELECT entry_hash FROM provenance ORDER BY rowid DESC LIMIT 1"
            )
            row = await cursor.fetchone()
            if row:
                self._last_entry_hash = row[0]

    async def append(self, entry: ProvenanceEntry) -> ProvenanceEntry:
        """Append a new entry to the provenance trail. Entries cannot be updated or deleted."""
        entry.previous_entry_hash = self._last_entry_hash
        entry.entry_hash = entry.compute_entry_hash(self.secret_key)

        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """INSERT INTO provenance
                   (id, timestamp, session_id, caller_id, upstream_model,
                    request_hash, response_hash, policy_verdicts, overall_verdict,
                    remediation_id, latency_ms, previous_entry_hash, entry_hash,
                    prompt_tokens, completion_tokens, total_tokens, estimated_cost_usd,
                    request_body, response_body, system_prompt,
                    temperature, max_tokens, top_p, frequency_penalty, presence_penalty,
                    stop_sequences, tool_calls, functions_available, model_info,
                    finish_reason, request_ip, user_agent,
                    system_fingerprint, model_routing, logprobs,
                    tenant_id, entities_masked)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                           ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                           ?, ?, ?, ?, ?)""",
                (
                    entry.id, entry.timestamp, entry.session_id, entry.caller_id,
                    entry.upstream_model, entry.request_hash, entry.response_hash,
                    json.dumps(entry.policy_verdicts, default=str),
                    entry.overall_verdict, entry.remediation_id, entry.latency_ms,
                    entry.previous_entry_hash, entry.entry_hash,
                    entry.prompt_tokens, entry.completion_tokens, entry.total_tokens,
                    entry.estimated_cost_usd,
                    entry.request_body, entry.response_body, entry.system_prompt,
                    entry.temperature, entry.max_tokens, entry.top_p,
                    entry.frequency_penalty, entry.presence_penalty,
                    json.dumps(entry.stop_sequences, default=str),
                    json.dumps(entry.tool_calls, default=str),
                    json.dumps(entry.functions_available, default=str),
                    json.dumps(entry.model_info, default=str),
                    entry.finish_reason, entry.request_ip, entry.user_agent,
                    entry.system_fingerprint,
                    json.dumps(entry.model_routing, default=str),
                    json.dumps(entry.logprobs, default=str),
                    entry.tenant_id,
                    json.dumps(entry.entities_masked, default=str),
                ),
            )
            await db.commit()

        self._last_entry_hash = entry.entry_hash
        logger.info(f"Provenance entry appended: {entry.id} verdict={entry.overall_verdict}")
        return entry

    async def get_entries(self, limit: int = 50, offset: int = 0,
                          verdict: str | None = None,
                          caller_id: str | None = None,
                          tenant_id: str | None = None) -> list[dict[str, Any]]:
        query = "SELECT * FROM provenance"
        params: list[Any] = []
        conditions = []

        if verdict:
            conditions.append("overall_verdict = ?")
            params.append(verdict)
        if caller_id:
            conditions.append("caller_id = ?")
            params.append(caller_id)
        if tenant_id:
            conditions.append("tenant_id = ?")
            params.append(tenant_id)

        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        query += " ORDER BY rowid DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(query, params)
            rows = await cursor.fetchall()
            return [self._row_to_dict(row) for row in rows]

    async def get_entry(self, entry_id: str) -> dict[str, Any] | None:
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                "SELECT * FROM provenance WHERE id = ?", (entry_id,)
            )
            row = await cursor.fetchone()
            return self._row_to_dict(row) if row else None

    async def verify_chain(self) -> dict[str, Any]:
        """Walk the entire chain and verify HMAC integrity of every entry."""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                "SELECT * FROM provenance ORDER BY rowid ASC"
            )
            rows = await cursor.fetchall()

        total = len(rows)
        if total == 0:
            return {"intact": True, "entries_verified": 0, "message": "No entries in chain"}

        previous_hash = ""
        for i, row in enumerate(rows):
            entry = ProvenanceEntry.from_dict(self._row_to_dict(row))
            # Verify chain link
            if entry.previous_entry_hash != previous_hash:
                return {
                    "intact": False,
                    "entries_verified": i,
                    "total_entries": total,
                    "tampered_at_position": i,
                    "tampered_entry_id": entry.id,
                    "message": f"Chain break at position {i}: previous_entry_hash mismatch",
                }
            # Verify entry hash
            expected_hash = entry.compute_entry_hash(self.secret_key)
            if entry.entry_hash != expected_hash:
                return {
                    "intact": False,
                    "entries_verified": i,
                    "total_entries": total,
                    "tampered_at_position": i,
                    "tampered_entry_id": entry.id,
                    "message": f"Tampered entry at position {i}: entry_hash mismatch",
                }
            previous_hash = entry.entry_hash

        first_entry = self._row_to_dict(rows[0])
        last_entry = self._row_to_dict(rows[-1])
        return {
            "intact": True,
            "entries_verified": total,
            "total_entries": total,
            "first_entry_timestamp": first_entry["timestamp"],
            "latest_entry_timestamp": last_entry["timestamp"],
            "message": f"Chain intact — {total} entries verified",
        }

    async def get_stats(self) -> dict[str, int]:
        async with aiosqlite.connect(self.db_path) as db:
            cursor = await db.execute("SELECT COUNT(*) FROM provenance")
            total = (await cursor.fetchone())[0]

            cursor = await db.execute(
                "SELECT COUNT(*) FROM provenance WHERE overall_verdict IN ('BLOCKED', 'VIOLATION')"
            )
            violations = (await cursor.fetchone())[0]

            cursor = await db.execute(
                "SELECT COUNT(*) FROM provenance WHERE remediation_id IS NOT NULL"
            )
            remediations = (await cursor.fetchone())[0]

            return {
                "total_intercepted": total,
                "violations_blocked": violations,
                "remediations_executed": remediations,
            }

    def _row_to_dict(self, row) -> dict[str, Any]:
        d = dict(row)
        # Parse JSON string fields back to Python objects
        for json_field in ("policy_verdicts", "stop_sequences", "tool_calls",
                           "functions_available", "model_info",
                           "model_routing", "logprobs", "entities_masked"):
            if isinstance(d.get(json_field), str):
                try:
                    d[json_field] = json.loads(d[json_field])
                except (json.JSONDecodeError, TypeError):
                    pass
        return d
