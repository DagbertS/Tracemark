"""Admin API — Multi-tenant company & user management with SOC compliance.

Two admin views:
1. Client Admin — single-tenant view for a customer's own admin
   (user management, subscription, licensing, billing)
2. Platform Admin — Tracemark-level view across all clients
   (all clients, filter by customer/cohort/region)
"""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from datetime import datetime, timezone, timedelta
from typing import Any, Optional, List

import aiosqlite
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

logger = logging.getLogger("tracemark.admin")

router = APIRouter(prefix="/api/admin", tags=["admin"])

# Module-level reference — wired up in main.py lifespan
db_path: str = "tracemark_provenance.db"

# ──────────────────────────────────────────────
# Schema
# ──────────────────────────────────────────────

ADMIN_SCHEMA = """
CREATE TABLE IF NOT EXISTS companies (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    slug TEXT UNIQUE NOT NULL,
    plan TEXT DEFAULT 'starter',
    status TEXT DEFAULT 'active',
    contact_email TEXT DEFAULT '',
    contact_phone TEXT DEFAULT '',
    address TEXT DEFAULT '',
    region TEXT DEFAULT 'NA',
    cohort TEXT DEFAULT 'general',
    max_users INTEGER DEFAULT 50,
    max_requests_per_month INTEGER DEFAULT 100000,
    soc_compliance_level TEXT DEFAULT 'SOC2-Type-I',
    data_retention_days INTEGER DEFAULT 90,
    mfa_required INTEGER DEFAULT 0,
    ip_whitelist TEXT DEFAULT '[]',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS subscriptions (
    id TEXT PRIMARY KEY,
    company_id TEXT NOT NULL,
    module TEXT NOT NULL,
    tier TEXT DEFAULT 'standard',
    status TEXT DEFAULT 'active',
    start_date TEXT NOT NULL,
    renewal_date TEXT NOT NULL,
    license_count INTEGER DEFAULT 1,
    unit_price_usd REAL DEFAULT 0.0,
    notes TEXT DEFAULT '',
    FOREIGN KEY (company_id) REFERENCES companies(id)
);
CREATE INDEX IF NOT EXISTS idx_sub_company ON subscriptions(company_id);

CREATE TABLE IF NOT EXISTS billing_transactions (
    id TEXT PRIMARY KEY,
    company_id TEXT NOT NULL,
    period_start TEXT NOT NULL,
    period_end TEXT NOT NULL,
    module TEXT NOT NULL,
    description TEXT DEFAULT '',
    quantity INTEGER DEFAULT 0,
    unit_price_usd REAL DEFAULT 0.0,
    total_usd REAL DEFAULT 0.0,
    created_at TEXT NOT NULL,
    FOREIGN KEY (company_id) REFERENCES companies(id)
);
CREATE INDEX IF NOT EXISTS idx_billing_company ON billing_transactions(company_id);
CREATE INDEX IF NOT EXISTS idx_billing_period ON billing_transactions(period_start);

CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    company_id TEXT NOT NULL,
    email TEXT NOT NULL,
    display_name TEXT NOT NULL,
    role TEXT DEFAULT 'viewer',
    status TEXT DEFAULT 'active',
    password_hash TEXT DEFAULT '',
    last_login TEXT,
    login_count INTEGER DEFAULT 0,
    failed_login_count INTEGER DEFAULT 0,
    locked_until TEXT,
    mfa_enabled INTEGER DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (company_id) REFERENCES companies(id)
);
CREATE INDEX IF NOT EXISTS idx_users_company ON users(company_id);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

CREATE TABLE IF NOT EXISTS audit_log (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    actor_id TEXT,
    actor_email TEXT,
    company_id TEXT,
    action TEXT NOT NULL,
    target_type TEXT,
    target_id TEXT,
    details TEXT DEFAULT '{}',
    ip_address TEXT DEFAULT '',
    user_agent TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_company ON audit_log(company_id);

CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    company_id TEXT NOT NULL,
    token_hash TEXT NOT NULL,
    ip_address TEXT DEFAULT '',
    user_agent TEXT DEFAULT '',
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    revoked INTEGER DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);

CREATE TABLE IF NOT EXISTS visitors (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    ip_address TEXT DEFAULT '',
    user_agent TEXT DEFAULT '',
    platform TEXT DEFAULT '',
    browser TEXT DEFAULT '',
    browser_version TEXT DEFAULT '',
    os TEXT DEFAULT '',
    device_type TEXT DEFAULT '',
    screen_width INTEGER DEFAULT 0,
    screen_height INTEGER DEFAULT 0,
    viewport_width INTEGER DEFAULT 0,
    viewport_height INTEGER DEFAULT 0,
    color_depth INTEGER DEFAULT 0,
    pixel_ratio REAL DEFAULT 1.0,
    language TEXT DEFAULT '',
    languages TEXT DEFAULT '[]',
    timezone TEXT DEFAULT '',
    timezone_offset INTEGER DEFAULT 0,
    referrer TEXT DEFAULT '',
    page_url TEXT DEFAULT '',
    page_path TEXT DEFAULT '',
    connection_type TEXT DEFAULT '',
    cookie_enabled INTEGER DEFAULT 1,
    do_not_track INTEGER DEFAULT 0,
    hardware_concurrency INTEGER DEFAULT 0,
    device_memory REAL DEFAULT 0,
    touch_support INTEGER DEFAULT 0,
    session_id TEXT DEFAULT '',
    visit_count INTEGER DEFAULT 1,
    country TEXT DEFAULT '',
    city TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_visitors_timestamp ON visitors(timestamp);
CREATE INDEX IF NOT EXISTS idx_visitors_session ON visitors(session_id);
CREATE INDEX IF NOT EXISTS idx_visitors_ip ON visitors(ip_address);
"""

ADMIN_MIGRATIONS = [
    "ALTER TABLE companies ADD COLUMN contact_phone TEXT DEFAULT ''",
    "ALTER TABLE companies ADD COLUMN address TEXT DEFAULT ''",
    "ALTER TABLE companies ADD COLUMN region TEXT DEFAULT 'NA'",
    "ALTER TABLE companies ADD COLUMN cohort TEXT DEFAULT 'general'",
    "ALTER TABLE companies ADD COLUMN max_requests_per_month INTEGER DEFAULT 100000",
    "ALTER TABLE companies ADD COLUMN soc_compliance_level TEXT DEFAULT 'SOC2-Type-I'",
    "ALTER TABLE companies ADD COLUMN data_retention_days INTEGER DEFAULT 90",
    "ALTER TABLE companies ADD COLUMN mfa_required INTEGER DEFAULT 0",
    "ALTER TABLE companies ADD COLUMN ip_whitelist TEXT DEFAULT '[]'",
    "ALTER TABLE users ADD COLUMN locked_until TEXT",
    "ALTER TABLE users ADD COLUMN mfa_enabled INTEGER DEFAULT 0",
]


async def initialize_admin_db(path: str):
    """Create admin tables and run migrations."""
    global db_path
    db_path = path
    async with aiosqlite.connect(db_path) as conn:
        await conn.executescript(ADMIN_SCHEMA)
        await conn.commit()
        for mig in ADMIN_MIGRATIONS:
            try:
                await conn.execute(mig)
                await conn.commit()
            except Exception:
                pass

    # Seed demo data if companies table is empty
    async with aiosqlite.connect(db_path) as conn:
        cur = await conn.execute("SELECT COUNT(*) FROM companies")
        count = (await cur.fetchone())[0]
        if count == 0:
            await _seed_demo_data(conn)
            await conn.commit()
    logger.info("Admin DB initialized")


async def _seed_demo_data(conn: aiosqlite.Connection):
    """Insert demo companies, users, subscriptions, billing for first run."""
    now = datetime.now(timezone.utc)
    now_iso = now.isoformat()
    q_start = datetime(2026, 1, 1, tzinfo=timezone.utc).isoformat()
    q_end = datetime(2026, 3, 31, tzinfo=timezone.utc).isoformat()

    companies = [
        ("comp-acme", "Acme Corp", "acme", "enterprise", "active", "admin@acme.io", "+1-555-0100",
         "123 Innovation Way, SF", "NA", "enterprise-pilot", 100, 500000, "SOC2-Type-II", 365, 1),
        ("comp-globex", "Globex Industries", "globex", "business", "active", "ops@globex.com", "+1-555-0200",
         "456 Tech Park, NYC", "NA", "mid-market", 50, 200000, "SOC2-Type-I", 180, 0),
        ("comp-initech", "Initech Solutions", "initech", "starter", "active", "hello@initech.dev", "+1-555-0300",
         "789 Startup Blvd, Austin", "NA", "startup", 25, 100000, "SOC2-Type-I", 90, 0),
        ("comp-umbrella", "Umbrella Research", "umbrella", "enterprise", "suspended", "compliance@umbrella.org", "+1-555-0400",
         "321 Lab Drive, Boston", "EU", "enterprise-pilot", 200, 1000000, "SOC2-Type-II", 730, 1),
        ("comp-nexgen", "NexGen AI Labs", "nexgen", "business", "active", "team@nexgen.ai", "+44-20-7946",
         "10 King's Cross, London", "EU", "mid-market", 40, 150000, "SOC2-Type-I", 180, 0),
        ("comp-pacifica", "Pacifica Health", "pacifica", "enterprise", "active", "admin@pacifica.health", "+61-2-8000",
         "200 George St, Sydney", "APAC", "healthcare", 75, 300000, "SOC2-Type-II", 365, 1),
    ]
    for c in companies:
        await conn.execute(
            """INSERT INTO companies (id, name, slug, plan, status, contact_email, contact_phone, address,
               region, cohort, max_users, max_requests_per_month, soc_compliance_level, data_retention_days, mfa_required,
               created_at, updated_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (*c, now_iso, now_iso),
        )

    # Subscriptions — module: interception (free), provenance, remediation
    subs = [
        # Acme — all three
        ("sub-a1", "comp-acme", "interception", "free", "active", "2025-07-01", "2026-07-01", 100, 0.0, "Free tier — unlimited"),
        ("sub-a2", "comp-acme", "provenance", "enterprise", "active", "2025-07-01", "2026-07-01", 100, 180.0, "$180/seat/yr"),
        ("sub-a3", "comp-acme", "remediation", "enterprise", "active", "2025-07-01", "2026-07-01", 50, 350.0, "$350/seat/yr"),
        # Globex — interception + provenance
        ("sub-g1", "comp-globex", "interception", "free", "active", "2025-10-01", "2026-10-01", 50, 0.0, "Free tier"),
        ("sub-g2", "comp-globex", "provenance", "business", "active", "2025-10-01", "2026-10-01", 50, 120.0, "$120/seat/yr"),
        ("sub-g3", "comp-globex", "remediation", "business", "active", "2025-10-01", "2026-10-01", 25, 220.0, "$220/seat/yr"),
        # Initech — interception only + provenance
        ("sub-i1", "comp-initech", "interception", "free", "active", "2026-01-15", "2027-01-15", 25, 0.0, "Free tier"),
        ("sub-i2", "comp-initech", "provenance", "starter", "active", "2026-01-15", "2027-01-15", 10, 50.0, "$50/seat/yr"),
        # Umbrella — all three
        ("sub-u1", "comp-umbrella", "interception", "free", "active", "2025-03-01", "2026-03-01", 200, 0.0, "Free tier"),
        ("sub-u2", "comp-umbrella", "provenance", "enterprise", "active", "2025-03-01", "2026-03-01", 200, 180.0, "$180/seat/yr"),
        ("sub-u3", "comp-umbrella", "remediation", "enterprise", "active", "2025-03-01", "2026-03-01", 100, 350.0, "$350/seat/yr"),
        # NexGen — all three
        ("sub-n1", "comp-nexgen", "interception", "free", "active", "2025-11-01", "2026-11-01", 40, 0.0, "Free tier"),
        ("sub-n2", "comp-nexgen", "provenance", "business", "active", "2025-11-01", "2026-11-01", 40, 120.0, "$120/seat/yr"),
        ("sub-n3", "comp-nexgen", "remediation", "business", "active", "2025-11-01", "2026-11-01", 20, 220.0, "$220/seat/yr"),
        # Pacifica — all three
        ("sub-p1", "comp-pacifica", "interception", "free", "active", "2025-09-01", "2026-09-01", 75, 0.0, "Free tier"),
        ("sub-p2", "comp-pacifica", "provenance", "enterprise", "active", "2025-09-01", "2026-09-01", 75, 180.0, "$180/seat/yr"),
        ("sub-p3", "comp-pacifica", "remediation", "enterprise", "active", "2025-09-01", "2026-09-01", 30, 350.0, "$350/seat/yr"),
    ]
    for s in subs:
        await conn.execute(
            """INSERT INTO subscriptions (id, company_id, module, tier, status, start_date, renewal_date, license_count, unit_price_usd, notes)
               VALUES (?,?,?,?,?,?,?,?,?,?)""", s,
        )

    # Billing transactions (Q1 2026)
    billing = [
        # Acme
        ("bill-a1", "comp-acme", q_start, q_end, "provenance", "Provenance — 100 seats Q1", 100, 45.0, 4500.0),
        ("bill-a2", "comp-acme", q_start, q_end, "remediation", "Remediation — 50 seats Q1", 50, 87.50, 4375.0),
        ("bill-a3", "comp-acme", q_start, q_end, "remediation", "Remediation exec — 47 actions @ $5.00", 47, 5.0, 235.0),
        ("bill-a4", "comp-acme", q_start, q_end, "interception", "Interception — free tier", 100, 0.0, 0.0),
        # Globex
        ("bill-g1", "comp-globex", q_start, q_end, "provenance", "Provenance — 50 seats Q1", 50, 30.0, 1500.0),
        ("bill-g2", "comp-globex", q_start, q_end, "remediation", "Remediation — 25 seats Q1", 25, 55.0, 1375.0),
        ("bill-g3", "comp-globex", q_start, q_end, "remediation", "Remediation exec — 12 actions @ $5.00", 12, 5.0, 60.0),
        ("bill-g4", "comp-globex", q_start, q_end, "interception", "Interception — free tier", 50, 0.0, 0.0),
        # Initech
        ("bill-i1", "comp-initech", q_start, q_end, "provenance", "Provenance — 10 seats Q1", 10, 12.50, 125.0),
        ("bill-i2", "comp-initech", q_start, q_end, "interception", "Interception — free tier", 25, 0.0, 0.0),
        # NexGen
        ("bill-n1", "comp-nexgen", q_start, q_end, "provenance", "Provenance — 40 seats Q1", 40, 30.0, 1200.0),
        ("bill-n2", "comp-nexgen", q_start, q_end, "remediation", "Remediation — 20 seats Q1", 20, 55.0, 1100.0),
        ("bill-n3", "comp-nexgen", q_start, q_end, "remediation", "Remediation exec — 8 actions @ $5.00", 8, 5.0, 40.0),
        # Pacifica
        ("bill-p1", "comp-pacifica", q_start, q_end, "provenance", "Provenance — 75 seats Q1", 75, 45.0, 3375.0),
        ("bill-p2", "comp-pacifica", q_start, q_end, "remediation", "Remediation — 30 seats Q1", 30, 87.50, 2625.0),
        ("bill-p3", "comp-pacifica", q_start, q_end, "remediation", "Remediation exec — 22 actions @ $5.00", 22, 5.0, 110.0),
    ]
    for b in billing:
        await conn.execute(
            """INSERT INTO billing_transactions (id, company_id, period_start, period_end, module, description, quantity, unit_price_usd, total_usd, created_at)
               VALUES (?,?,?,?,?,?,?,?,?,?)""", (*b, now_iso),
        )

    users = [
        # Acme
        ("user-a1", "comp-acme", "alice@acme.io", "Alice Chen", "admin", "active", 45, 0),
        ("user-a2", "comp-acme", "bob@acme.io", "Bob Martinez", "operator", "active", 23, 0),
        ("user-a3", "comp-acme", "carol@acme.io", "Carol Wu", "viewer", "active", 12, 0),
        ("user-a4", "comp-acme", "dave@acme.io", "Dave Johnson", "operator", "suspended", 8, 3),
        # Globex
        ("user-g1", "comp-globex", "emma@globex.com", "Emma Davis", "admin", "active", 67, 0),
        ("user-g2", "comp-globex", "frank@globex.com", "Frank Lee", "operator", "active", 34, 0),
        ("user-g3", "comp-globex", "grace@globex.com", "Grace Kim", "viewer", "active", 5, 0),
        # Initech
        ("user-i1", "comp-initech", "hank@initech.dev", "Hank Patel", "admin", "active", 89, 0),
        ("user-i2", "comp-initech", "iris@initech.dev", "Iris Nguyen", "operator", "active", 41, 0),
        # Umbrella
        ("user-u1", "comp-umbrella", "jake@umbrella.org", "Jake Thompson", "admin", "active", 120, 0),
        ("user-u2", "comp-umbrella", "kate@umbrella.org", "Kate Robinson", "operator", "suspended", 56, 5),
        # NexGen
        ("user-n1", "comp-nexgen", "liam@nexgen.ai", "Liam Parker", "admin", "active", 33, 0),
        ("user-n2", "comp-nexgen", "mia@nexgen.ai", "Mia Foster", "operator", "active", 18, 0),
        # Pacifica
        ("user-p1", "comp-pacifica", "noah@pacifica.health", "Noah Williams", "admin", "active", 92, 0),
        ("user-p2", "comp-pacifica", "olivia@pacifica.health", "Olivia Brown", "operator", "active", 51, 0),
        ("user-p3", "comp-pacifica", "peter@pacifica.health", "Peter Chang", "viewer", "active", 14, 0),
    ]
    for u in users:
        pw_hash = hashlib.sha256(("demo_" + u[0]).encode()).hexdigest()
        await conn.execute(
            """INSERT INTO users (id, company_id, email, display_name, role, status, password_hash,
               login_count, failed_login_count, created_at, updated_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (*u[:6], pw_hash, u[6], u[7], now_iso, now_iso),
        )

    # Seed audit log
    audit_events = [
        ("user-a1", "alice@acme.io", "comp-acme", "user.login", "user", "user-a1", {}),
        ("user-a1", "alice@acme.io", "comp-acme", "company.settings.updated", "company", "comp-acme", {"field": "mfa_required", "old": False, "new": True}),
        ("user-a1", "alice@acme.io", "comp-acme", "user.suspended", "user", "user-a4", {"reason": "Policy violation"}),
        ("user-g1", "emma@globex.com", "comp-globex", "user.created", "user", "user-g3", {"role": "viewer"}),
        ("user-g1", "emma@globex.com", "comp-globex", "user.login", "user", "user-g1", {}),
        ("user-i1", "hank@initech.dev", "comp-initech", "user.password_reset", "user", "user-i2", {}),
        ("user-u1", "jake@umbrella.org", "comp-umbrella", "company.suspended", "company", "comp-umbrella", {"reason": "Compliance review"}),
        ("user-a2", "bob@acme.io", "comp-acme", "user.login", "user", "user-a2", {}),
        ("user-a1", "alice@acme.io", "comp-acme", "policy.created", "policy", "pol-123", {"name": "PII Detection v2"}),
        ("user-g2", "frank@globex.com", "comp-globex", "user.login", "user", "user-g2", {}),
        ("user-n1", "liam@nexgen.ai", "comp-nexgen", "user.login", "user", "user-n1", {}),
        ("user-p1", "noah@pacifica.health", "comp-pacifica", "subscription.renewed", "subscription", "sub-p2", {"module": "provenance"}),
    ]
    for i, evt in enumerate(audit_events):
        aid = f"audit-{uuid.uuid4().hex[:12]}"
        await conn.execute(
            """INSERT INTO audit_log (id, timestamp, actor_id, actor_email, company_id, action, target_type, target_id, details, ip_address)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (aid, now_iso, evt[0], evt[1], evt[2], evt[3], evt[4], evt[5], json.dumps(evt[6]), f"10.0.{i}.1"),
        )


# ──────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────

async def _audit(action: str, actor_id: str = "system", actor_email: str = "system",
                 company_id: str = "", target_type: str = "", target_id: str = "",
                 details: Optional[dict] = None, ip: str = ""):
    async with aiosqlite.connect(db_path) as conn:
        await conn.execute(
            """INSERT INTO audit_log (id, timestamp, actor_id, actor_email, company_id, action, target_type, target_id, details, ip_address)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (f"audit-{uuid.uuid4().hex[:12]}", datetime.now(timezone.utc).isoformat(),
             actor_id, actor_email, company_id, action, target_type, target_id,
             json.dumps(details or {}), ip),
        )
        await conn.commit()


def _row_dict(row) -> dict:
    return dict(row)


# ──────────────────────────────────────────────
# Request Models
# ──────────────────────────────────────────────

class CompanyCreate(BaseModel):
    name: str
    slug: str
    plan: str = "starter"
    contact_email: str = ""
    contact_phone: str = ""
    address: str = ""
    region: str = "NA"
    cohort: str = "general"
    max_users: int = 50
    max_requests_per_month: int = 100000
    soc_compliance_level: str = "SOC2-Type-I"
    data_retention_days: int = 90
    mfa_required: bool = False

class CompanyUpdate(BaseModel):
    name: Optional[str] = None
    plan: Optional[str] = None
    status: Optional[str] = None
    contact_email: Optional[str] = None
    contact_phone: Optional[str] = None
    address: Optional[str] = None
    region: Optional[str] = None
    cohort: Optional[str] = None
    max_users: Optional[int] = None
    max_requests_per_month: Optional[int] = None
    soc_compliance_level: Optional[str] = None
    data_retention_days: Optional[int] = None
    mfa_required: Optional[bool] = None
    ip_whitelist: Optional[List[str]] = None

class UserCreate(BaseModel):
    email: str
    display_name: str
    role: str = "viewer"
    company_id: str

class UserUpdate(BaseModel):
    display_name: Optional[str] = None
    role: Optional[str] = None
    status: Optional[str] = None
    mfa_enabled: Optional[bool] = None


# ──────────────────────────────────────────────
# Company endpoints
# ──────────────────────────────────────────────

@router.get("/companies")
async def list_companies(region: Optional[str] = None, cohort: Optional[str] = None, status: Optional[str] = None):
    query = "SELECT * FROM companies"
    params: list = []
    conditions = []
    if region:
        conditions.append("region = ?")
        params.append(region)
    if cohort:
        conditions.append("cohort = ?")
        params.append(cohort)
    if status:
        conditions.append("status = ?")
        params.append(status)
    if conditions:
        query += " WHERE " + " AND ".join(conditions)
    query += " ORDER BY name"

    async with aiosqlite.connect(db_path) as conn:
        conn.row_factory = aiosqlite.Row
        cur = await conn.execute(query, params)
        rows = await cur.fetchall()
        companies = [_row_dict(r) for r in rows]

    for c in companies:
        async with aiosqlite.connect(db_path) as conn:
            cur = await conn.execute("SELECT COUNT(*) FROM users WHERE company_id = ?", (c["id"],))
            c["user_count"] = (await cur.fetchone())[0]
            cur = await conn.execute("SELECT COUNT(*) FROM users WHERE company_id = ? AND status = 'active'", (c["id"],))
            c["active_users"] = (await cur.fetchone())[0]
        try:
            c["ip_whitelist"] = json.loads(c.get("ip_whitelist", "[]"))
        except (json.JSONDecodeError, TypeError):
            c["ip_whitelist"] = []

    return companies


@router.get("/companies/{company_id}")
async def get_company(company_id: str):
    async with aiosqlite.connect(db_path) as conn:
        conn.row_factory = aiosqlite.Row
        cur = await conn.execute("SELECT * FROM companies WHERE id = ?", (company_id,))
        row = await cur.fetchone()
    if not row:
        raise HTTPException(404, "Company not found")
    c = _row_dict(row)
    try:
        c["ip_whitelist"] = json.loads(c.get("ip_whitelist", "[]"))
    except (json.JSONDecodeError, TypeError):
        c["ip_whitelist"] = []
    return c


@router.post("/companies")
async def create_company(body: CompanyCreate):
    cid = f"comp-{uuid.uuid4().hex[:8]}"
    now = datetime.now(timezone.utc).isoformat()
    async with aiosqlite.connect(db_path) as conn:
        try:
            await conn.execute(
                """INSERT INTO companies (id, name, slug, plan, status, contact_email, contact_phone, address,
                   region, cohort, max_users, max_requests_per_month, soc_compliance_level, data_retention_days, mfa_required,
                   created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (cid, body.name, body.slug, body.plan, "active", body.contact_email, body.contact_phone,
                 body.address, body.region, body.cohort, body.max_users, body.max_requests_per_month,
                 body.soc_compliance_level, body.data_retention_days, int(body.mfa_required), now, now),
            )
            await conn.commit()
        except aiosqlite.IntegrityError:
            raise HTTPException(409, "Company slug already exists")
    await _audit("company.created", target_type="company", target_id=cid,
                 details={"name": body.name, "slug": body.slug})
    return {"id": cid, "status": "created"}


@router.put("/companies/{company_id}")
async def update_company(company_id: str, body: CompanyUpdate):
    updates = body.dict(exclude_none=True)
    if not updates:
        raise HTTPException(400, "No fields to update")
    if "ip_whitelist" in updates:
        updates["ip_whitelist"] = json.dumps(updates["ip_whitelist"])
    if "mfa_required" in updates:
        updates["mfa_required"] = int(updates["mfa_required"])
    updates["updated_at"] = datetime.now(timezone.utc).isoformat()
    set_clause = ", ".join(f"{k} = ?" for k in updates)
    vals = list(updates.values()) + [company_id]
    async with aiosqlite.connect(db_path) as conn:
        await conn.execute(f"UPDATE companies SET {set_clause} WHERE id = ?", vals)
        await conn.commit()
    await _audit("company.updated", company_id=company_id, target_type="company",
                 target_id=company_id, details=updates)
    return {"status": "updated"}


@router.delete("/companies/{company_id}")
async def delete_company(company_id: str):
    async with aiosqlite.connect(db_path) as conn:
        await conn.execute("DELETE FROM billing_transactions WHERE company_id = ?", (company_id,))
        await conn.execute("DELETE FROM subscriptions WHERE company_id = ?", (company_id,))
        await conn.execute("DELETE FROM users WHERE company_id = ?", (company_id,))
        await conn.execute("DELETE FROM companies WHERE id = ?", (company_id,))
        await conn.commit()
    await _audit("company.deleted", target_type="company", target_id=company_id)
    return {"status": "deleted"}


# ──────────────────────────────────────────────
# Subscription endpoints
# ──────────────────────────────────────────────

@router.get("/companies/{company_id}/subscriptions")
async def list_subscriptions(company_id: str):
    async with aiosqlite.connect(db_path) as conn:
        conn.row_factory = aiosqlite.Row
        cur = await conn.execute("SELECT * FROM subscriptions WHERE company_id = ? ORDER BY module", (company_id,))
        return [_row_dict(r) for r in await cur.fetchall()]


# ──────────────────────────────────────────────
# Billing endpoints
# ──────────────────────────────────────────────

@router.get("/companies/{company_id}/billing")
async def list_billing(company_id: str):
    async with aiosqlite.connect(db_path) as conn:
        conn.row_factory = aiosqlite.Row
        cur = await conn.execute(
            "SELECT * FROM billing_transactions WHERE company_id = ? ORDER BY period_start DESC, module",
            (company_id,),
        )
        rows = await cur.fetchall()
    return [_row_dict(r) for r in rows]


@router.get("/billing/summary")
async def billing_summary():
    """Platform-wide billing summary for Tracemark admin."""
    async with aiosqlite.connect(db_path) as conn:
        conn.row_factory = aiosqlite.Row
        cur = await conn.execute(
            """SELECT company_id, module, SUM(total_usd) as total, SUM(quantity) as qty
               FROM billing_transactions GROUP BY company_id, module ORDER BY company_id"""
        )
        rows = await cur.fetchall()
    return [_row_dict(r) for r in rows]


# ──────────────────────────────────────────────
# User endpoints
# ──────────────────────────────────────────────

@router.get("/companies/{company_id}/users")
async def list_users(company_id: str):
    async with aiosqlite.connect(db_path) as conn:
        conn.row_factory = aiosqlite.Row
        cur = await conn.execute(
            "SELECT * FROM users WHERE company_id = ? ORDER BY display_name", (company_id,)
        )
        rows = await cur.fetchall()
    users = []
    for r in rows:
        u = _row_dict(r)
        u.pop("password_hash", None)
        users.append(u)
    return users


@router.post("/companies/{company_id}/users")
async def create_user(company_id: str, body: UserCreate):
    uid = f"user-{uuid.uuid4().hex[:8]}"
    now = datetime.now(timezone.utc).isoformat()
    pw_hash = hashlib.sha256(f"welcome_{uid}".encode()).hexdigest()
    async with aiosqlite.connect(db_path) as conn:
        await conn.execute(
            """INSERT INTO users (id, company_id, email, display_name, role, status, password_hash,
               login_count, failed_login_count, created_at, updated_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (uid, company_id, body.email, body.display_name, body.role, "active", pw_hash, 0, 0, now, now),
        )
        await conn.commit()
    await _audit("user.created", company_id=company_id, target_type="user", target_id=uid,
                 details={"email": body.email, "role": body.role})
    return {"id": uid, "status": "created"}


@router.put("/users/{user_id}")
async def update_user(user_id: str, body: UserUpdate):
    updates = body.dict(exclude_none=True)
    if not updates:
        raise HTTPException(400, "No fields to update")
    if "mfa_enabled" in updates:
        updates["mfa_enabled"] = int(updates["mfa_enabled"])
    updates["updated_at"] = datetime.now(timezone.utc).isoformat()
    set_clause = ", ".join(f"{k} = ?" for k in updates)
    vals = list(updates.values()) + [user_id]
    async with aiosqlite.connect(db_path) as conn:
        await conn.execute(f"UPDATE users SET {set_clause} WHERE id = ?", vals)
        await conn.commit()
    await _audit("user.updated", target_type="user", target_id=user_id, details=updates)
    return {"status": "updated"}


@router.post("/users/{user_id}/suspend")
async def suspend_user(user_id: str):
    now = datetime.now(timezone.utc).isoformat()
    async with aiosqlite.connect(db_path) as conn:
        await conn.execute("UPDATE users SET status = 'suspended', updated_at = ? WHERE id = ?", (now, user_id))
        await conn.commit()
    await _audit("user.suspended", target_type="user", target_id=user_id)
    return {"status": "suspended"}


@router.post("/users/{user_id}/activate")
async def activate_user(user_id: str):
    now = datetime.now(timezone.utc).isoformat()
    async with aiosqlite.connect(db_path) as conn:
        await conn.execute(
            "UPDATE users SET status = 'active', failed_login_count = 0, locked_until = NULL, updated_at = ? WHERE id = ?",
            (now, user_id),
        )
        await conn.commit()
    await _audit("user.activated", target_type="user", target_id=user_id)
    return {"status": "activated"}


@router.post("/users/{user_id}/reset-password")
async def reset_password(user_id: str):
    now = datetime.now(timezone.utc).isoformat()
    new_hash = hashlib.sha256(f"reset_{uuid.uuid4().hex}".encode()).hexdigest()
    async with aiosqlite.connect(db_path) as conn:
        await conn.execute(
            "UPDATE users SET password_hash = ?, failed_login_count = 0, locked_until = NULL, updated_at = ? WHERE id = ?",
            (new_hash, now, user_id),
        )
        await conn.commit()
    await _audit("user.password_reset", target_type="user", target_id=user_id)
    return {"status": "password_reset", "message": "Temporary password generated"}


@router.delete("/users/{user_id}")
async def delete_user(user_id: str):
    async with aiosqlite.connect(db_path) as conn:
        await conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
        await conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
        await conn.commit()
    await _audit("user.deleted", target_type="user", target_id=user_id)
    return {"status": "deleted"}


# ──────────────────────────────────────────────
# Audit log
# ──────────────────────────────────────────────

@router.get("/audit-log")
async def get_audit_log(company_id: Optional[str] = None, limit: int = 100):
    query = "SELECT * FROM audit_log"
    params: list = []
    if company_id:
        query += " WHERE company_id = ?"
        params.append(company_id)
    query += " ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)
    async with aiosqlite.connect(db_path) as conn:
        conn.row_factory = aiosqlite.Row
        cur = await conn.execute(query, params)
        rows = await cur.fetchall()
    entries = []
    for r in rows:
        e = _row_dict(r)
        if isinstance(e.get("details"), str):
            try:
                e["details"] = json.loads(e["details"])
            except (json.JSONDecodeError, TypeError):
                pass
        entries.append(e)
    return entries


# ──────────────────────────────────────────────
# Platform dashboard (Tracemark admin)
# ──────────────────────────────────────────────

@router.get("/dashboard")
async def admin_dashboard():
    async with aiosqlite.connect(db_path) as conn:
        cur = await conn.execute("SELECT COUNT(*) FROM companies")
        total_companies = (await cur.fetchone())[0]
        cur = await conn.execute("SELECT COUNT(*) FROM companies WHERE status = 'active'")
        active_companies = (await cur.fetchone())[0]
        cur = await conn.execute("SELECT COUNT(*) FROM users")
        total_users = (await cur.fetchone())[0]
        cur = await conn.execute("SELECT COUNT(*) FROM users WHERE status = 'active'")
        active_users = (await cur.fetchone())[0]
        cur = await conn.execute("SELECT COUNT(*) FROM users WHERE status = 'suspended'")
        suspended_users = (await cur.fetchone())[0]
        cur = await conn.execute("SELECT COUNT(*) FROM audit_log")
        audit_entries = (await cur.fetchone())[0]
        cur = await conn.execute("SELECT COALESCE(SUM(total_usd),0) FROM billing_transactions")
        total_revenue = round((await cur.fetchone())[0], 2)
        cur = await conn.execute("SELECT COUNT(DISTINCT company_id) FROM subscriptions WHERE status = 'active'")
        paying_companies = (await cur.fetchone())[0]

    async with aiosqlite.connect(db_path) as conn:
        cur = await conn.execute("SELECT COUNT(*), COALESCE(SUM(total_tokens),0), COALESCE(SUM(estimated_cost_usd),0) FROM provenance")
        row = await cur.fetchone()
        total_requests = row[0] if row else 0
        total_tokens = row[1] if row else 0
        total_cost = round(row[2], 4) if row else 0

    # Get distinct regions and cohorts for filters
    async with aiosqlite.connect(db_path) as conn:
        cur = await conn.execute("SELECT DISTINCT region FROM companies ORDER BY region")
        regions = [r[0] for r in await cur.fetchall()]
        cur = await conn.execute("SELECT DISTINCT cohort FROM companies ORDER BY cohort")
        cohorts = [r[0] for r in await cur.fetchall()]

    return {
        "total_companies": total_companies,
        "active_companies": active_companies,
        "paying_companies": paying_companies,
        "total_users": total_users,
        "active_users": active_users,
        "suspended_users": suspended_users,
        "audit_entries": audit_entries,
        "total_requests": total_requests,
        "total_tokens": total_tokens,
        "total_cost": total_cost,
        "total_revenue": total_revenue,
        "regions": regions,
        "cohorts": cohorts,
    }


# ──────────────────────────────────────────────
# Visitor Tracking
# ──────────────────────────────────────────────

def _parse_user_agent(ua: str) -> dict:
    """Extract browser, OS, and device info from user-agent string."""
    browser = browser_version = os_name = device_type = ""

    # OS detection
    if "Windows" in ua:
        os_name = "Windows"
    elif "Macintosh" in ua or "Mac OS" in ua:
        os_name = "macOS"
    elif "Linux" in ua:
        os_name = "Linux"
    elif "Android" in ua:
        os_name = "Android"
    elif "iPhone" in ua or "iPad" in ua:
        os_name = "iOS"
    elif "CrOS" in ua:
        os_name = "ChromeOS"

    # Browser detection
    if "Edg/" in ua:
        browser = "Edge"
        idx = ua.find("Edg/")
        browser_version = ua[idx+4:].split(" ")[0]
    elif "OPR/" in ua or "Opera" in ua:
        browser = "Opera"
        idx = ua.find("OPR/")
        if idx > -1:
            browser_version = ua[idx+4:].split(" ")[0]
    elif "Chrome/" in ua and "Safari/" in ua:
        browser = "Chrome"
        idx = ua.find("Chrome/")
        browser_version = ua[idx+7:].split(" ")[0]
    elif "Firefox/" in ua:
        browser = "Firefox"
        idx = ua.find("Firefox/")
        browser_version = ua[idx+8:].split(" ")[0]
    elif "Safari/" in ua and "Chrome" not in ua:
        browser = "Safari"
        idx = ua.find("Version/")
        if idx > -1:
            browser_version = ua[idx+8:].split(" ")[0]

    # Device type
    if "Mobile" in ua or "Android" in ua and "Mobile" in ua:
        device_type = "Mobile"
    elif "iPad" in ua or "Tablet" in ua:
        device_type = "Tablet"
    elif ua:
        device_type = "Desktop"

    return {
        "browser": browser, "browser_version": browser_version,
        "os": os_name, "device_type": device_type,
    }


class VisitorPayload(BaseModel):
    screen_width: int = 0
    screen_height: int = 0
    viewport_width: int = 0
    viewport_height: int = 0
    color_depth: int = 0
    pixel_ratio: float = 1.0
    language: str = ""
    languages: List[str] = []
    timezone: str = ""
    timezone_offset: int = 0
    referrer: str = ""
    page_url: str = ""
    page_path: str = ""
    connection_type: str = ""
    cookie_enabled: bool = True
    do_not_track: bool = False
    hardware_concurrency: int = 0
    device_memory: float = 0
    touch_support: bool = False
    session_id: str = ""


@router.post("/visitors/track")
async def track_visitor(payload: VisitorPayload, request: Request):
    """Record a page visit with all capturable browser metadata."""
    now_iso = datetime.now(timezone.utc).isoformat()
    visitor_id = str(uuid.uuid4())

    # Extract IP
    ip = request.headers.get("x-forwarded-for", "").split(",")[0].strip()
    if not ip:
        ip = request.client.host if request.client else ""

    # Parse UA
    ua_raw = request.headers.get("user-agent", "")
    ua_info = _parse_user_agent(ua_raw)

    # Check for existing session to increment visit count
    visit_count = 1
    if payload.session_id:
        async with aiosqlite.connect(db_path) as conn:
            cur = await conn.execute(
                "SELECT COUNT(*) FROM visitors WHERE session_id = ?",
                (payload.session_id,),
            )
            row = await cur.fetchone()
            visit_count = (row[0] or 0) + 1

    async with aiosqlite.connect(db_path) as conn:
        await conn.execute(
            """INSERT INTO visitors (
                id, timestamp, ip_address, user_agent, platform, browser, browser_version,
                os, device_type, screen_width, screen_height, viewport_width, viewport_height,
                color_depth, pixel_ratio, language, languages, timezone, timezone_offset,
                referrer, page_url, page_path, connection_type, cookie_enabled, do_not_track,
                hardware_concurrency, device_memory, touch_support, session_id, visit_count
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                visitor_id, now_iso, ip, ua_raw, ua_info.get("os", ""),
                ua_info["browser"], ua_info["browser_version"], ua_info["os"],
                ua_info["device_type"],
                payload.screen_width, payload.screen_height,
                payload.viewport_width, payload.viewport_height,
                payload.color_depth, payload.pixel_ratio,
                payload.language, json.dumps(payload.languages),
                payload.timezone, payload.timezone_offset,
                payload.referrer, payload.page_url, payload.page_path,
                payload.connection_type,
                1 if payload.cookie_enabled else 0,
                1 if payload.do_not_track else 0,
                payload.hardware_concurrency, payload.device_memory,
                1 if payload.touch_support else 0,
                payload.session_id, visit_count,
            ),
        )
        await conn.commit()

    return {"status": "ok", "visitor_id": visitor_id, "visit_count": visit_count}


@router.get("/visitors")
async def list_visitors(limit: int = 100, offset: int = 0):
    """Return recent visitors with all captured metadata."""
    async with aiosqlite.connect(db_path) as conn:
        conn.row_factory = aiosqlite.Row
        cur = await conn.execute(
            "SELECT * FROM visitors ORDER BY timestamp DESC LIMIT ? OFFSET ?",
            (limit, offset),
        )
        rows = [dict(r) for r in await cur.fetchall()]
        cur2 = await conn.execute("SELECT COUNT(*) FROM visitors")
        total = (await cur2.fetchone())[0]

        # Summary stats
        cur3 = await conn.execute("SELECT COUNT(DISTINCT ip_address) FROM visitors")
        unique_ips = (await cur3.fetchone())[0]
        cur4 = await conn.execute("SELECT COUNT(DISTINCT session_id) FROM visitors WHERE session_id != ''")
        unique_sessions = (await cur4.fetchone())[0]

    return {
        "visitors": rows,
        "total": total,
        "unique_ips": unique_ips,
        "unique_sessions": unique_sessions,
    }
