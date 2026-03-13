"""Tests for the Tracemark tamper-proof provenance store."""

import os
import pytest
import pytest_asyncio
import aiosqlite

from app.provenance import ProvenanceStore, ProvenanceEntry

TEST_DB = "test_provenance.db"
SECRET = "test-secret-key"


@pytest_asyncio.fixture
async def store():
    if os.path.exists(TEST_DB):
        os.remove(TEST_DB)
    s = ProvenanceStore(db_path=TEST_DB, secret_key=SECRET)
    await s.initialize()
    yield s
    if os.path.exists(TEST_DB):
        os.remove(TEST_DB)


def make_entry(**kwargs) -> ProvenanceEntry:
    defaults = {
        "session_id": "test-session",
        "caller_id": "test-caller",
        "upstream_model": "gpt-4o",
        "request_hash": ProvenanceEntry.hash_content("test request"),
        "response_hash": ProvenanceEntry.hash_content("test response"),
        "policy_verdicts": [{"policy_id": "test", "result": "PASS"}],
        "overall_verdict": "PASS",
        "latency_ms": 42,
    }
    defaults.update(kwargs)
    return ProvenanceEntry(**defaults)


@pytest.mark.asyncio
async def test_chain_integrity_valid(store):
    for i in range(5):
        await store.append(make_entry())

    result = await store.verify_chain()
    assert result["intact"] is True
    assert result["entries_verified"] == 5


@pytest.mark.asyncio
async def test_chain_integrity_tampered(store):
    for i in range(5):
        await store.append(make_entry())

    # Tamper with the third entry directly in SQLite
    async with aiosqlite.connect(TEST_DB) as db:
        cursor = await db.execute("SELECT id FROM provenance ORDER BY rowid LIMIT 1 OFFSET 2")
        row = await cursor.fetchone()
        entry_id = row[0]
        await db.execute(
            "UPDATE provenance SET caller_id = 'TAMPERED' WHERE id = ?", (entry_id,)
        )
        await db.commit()

    result = await store.verify_chain()
    assert result["intact"] is False
    assert result["tampered_at_position"] == 2


@pytest.mark.asyncio
async def test_append_only(store):
    entry = await store.append(make_entry())

    # Attempting to update should not be possible through the store API
    # (no update method exists). Verify by checking the entry exists unchanged.
    retrieved = await store.get_entry(entry.id)
    assert retrieved is not None
    assert retrieved["caller_id"] == "test-caller"
    assert retrieved["entry_hash"] == entry.entry_hash


@pytest.mark.asyncio
async def test_hash_chain_links(store):
    e1 = await store.append(make_entry())
    e2 = await store.append(make_entry())

    assert e1.previous_entry_hash == ""
    assert e2.previous_entry_hash == e1.entry_hash


@pytest.mark.asyncio
async def test_stats(store):
    await store.append(make_entry(overall_verdict="PASS"))
    await store.append(make_entry(overall_verdict="BLOCKED"))
    await store.append(make_entry(overall_verdict="VIOLATION"))

    stats = await store.get_stats()
    assert stats["total_intercepted"] == 3
    assert stats["violations_blocked"] == 2
