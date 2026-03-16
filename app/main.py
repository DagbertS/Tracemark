"""Tracemark — AI governance, control, and remediation infrastructure.

Entry point for the FastAPI application. Initializes all subsystems:
policy engine, provenance store, remediation engine, sanitization layer,
connector framework, and the interception proxy.
"""

import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path

import yaml
from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from . import proxy
from .api import health, provenance as provenance_api, policies as policies_api, remediation as remediation_api, admin as admin_api
from .api import connectors as connectors_api
from .policy_engine import PolicyEngine
from .provenance import ProvenanceStore
from .remediation import SAGAOrchestrator, ActionRegistry
from .remediation.actions.email_action import retract_email
from .remediation.actions.crm_action import restore_crm_record
from .remediation.actions.notify_action import send_compliance_override
from .remediation.actions.api_action import revoke_api_call
from .remediation.actions.document_action import revoke_document_access
from .remediation.actions.database_action import rollback_database_change
from .remediation.actions.ticket_action import void_ticket
from .remediation.actions.permission_action import revert_permission_change
from .sanitization import SanitizationEngine, VaultStore
from .connectors.registry import ConnectorRegistry

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger("tracemark")


def load_config() -> dict:
    config_path = os.environ.get("TRACEMARK_CONFIG", "config.yaml")
    with open(config_path) as f:
        return yaml.safe_load(f)


def build_action_registry(config: dict) -> ActionRegistry:
    registry = ActionRegistry()
    action_map = {
        "retract_email": retract_email,
        "restore_crm_record": restore_crm_record,
        "send_compliance_override": send_compliance_override,
        "revoke_api_call": revoke_api_call,
        "revoke_document_access": revoke_document_access,
        "rollback_database_change": rollback_database_change,
        "void_ticket": void_ticket,
        "revert_permission_change": revert_permission_change,
    }
    for action_type, action_cfg in config.get("action_registry", {}).items():
        comp_name = action_cfg.get("compensating_action")
        comp_fn = action_map.get(comp_name)
        if comp_fn:
            registry.register(
                action_type=action_type,
                description=action_cfg.get("description", ""),
                compensate_fn=comp_fn,
                notify_compliance=action_cfg.get("notify_compliance", False),
            )
    return registry


@asynccontextmanager
async def lifespan(app: FastAPI):
    config = load_config()
    tracemark_cfg = config.get("tracemark", {})

    # Secret key from env or config — never hardcoded in application code
    secret_key = os.environ.get(
        "TRACEMARK_SECRET_KEY", tracemark_cfg.get("secret_key", "")
    )

    log_level = tracemark_cfg.get("log_level", "INFO")
    logging.getLogger("tracemark").setLevel(getattr(logging, log_level, logging.INFO))

    # Initialize policy engine
    pe = PolicyEngine(config.get("policies", []))

    # Initialize provenance store
    db_path = os.environ.get("TRACEMARK_DB_PATH", "tracemark_provenance.db")
    ps = ProvenanceStore(db_path=db_path, secret_key=secret_key)
    await ps.initialize()

    # Initialize remediation engine
    ar = build_action_registry(config)
    so = SAGAOrchestrator(registry=ar)

    # Initialize sanitization layer
    sanitization_cfg = config.get("sanitization", {})
    vault = VaultStore(default_ttl=sanitization_cfg.get("ttl", 300))
    se = SanitizationEngine(
        vault=vault,
        enabled=sanitization_cfg.get("enabled", True),
    )

    # Initialize connector registry
    cr = ConnectorRegistry(db_path=db_path)
    await cr.initialize()

    # Wire up module-level references
    proxy.policy_engine = pe
    proxy.provenance_store = ps
    proxy.saga_orchestrator = so
    proxy.sanitization_engine = se
    proxy.upstream_config = {
        "base_url": config.get("upstream", {}).get("base_url", ""),
        "mock_mode": config.get("upstream", {}).get("mock_mode", True),
        "api_keys": {
            "openai": os.environ.get("OPENAI_API_KEY", ""),
            "anthropic": os.environ.get("ANTHROPIC_API_KEY", ""),
            "google": os.environ.get("GOOGLE_API_KEY", ""),
        },
    }

    provenance_api.provenance_store = ps
    policies_api.policy_engine = pe
    policies_api.provenance_store = ps
    remediation_api.saga_orchestrator = so
    remediation_api.action_registry = ar
    remediation_api.provenance_store = ps
    connectors_api.connector_registry = cr

    # Initialize admin multi-tenant DB
    await admin_api.initialize_admin_db(db_path)

    # Initialize persistent visitor DB (separate file for deploy persistence)
    # On Railway, /data is a mounted volume that survives deploys
    # Locally, fall back to a file next to the main DB
    default_visitor_path = "/data/visitors.db" if os.path.isdir("/data") else "visitors.db"
    visitor_db = os.environ.get("VISITOR_DB_PATH", default_visitor_path)
    await admin_api.initialize_visitor_db(visitor_db)

    logger.info("Tracemark infrastructure initialized")
    logger.info(f"  Policies loaded: {len(pe.policies)}")
    logger.info(f"  Mock mode: {proxy.upstream_config['mock_mode']}")
    logger.info(f"  Sanitization: {'enabled' if se.enabled else 'disabled'}")
    logger.info(f"  Provenance DB: {db_path}")
    logger.info(f"  Connectors registered: {len(cr.list_connectors())}")
    logger.info(f"  Visitor DB: {visitor_db}")

    yield

    logger.info("Tracemark shutting down")


app = FastAPI(
    title="Tracemark",
    description="AI governance, control, and remediation infrastructure",
    version="0.1.0-mvp",
    lifespan=lifespan,
)

# Include routers
app.include_router(proxy.router)
app.include_router(health.router)
app.include_router(provenance_api.router)
app.include_router(policies_api.router)
app.include_router(remediation_api.router)
app.include_router(admin_api.router)
app.include_router(connectors_api.router)

# Serve static UI
static_dir = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")


@app.get("/")
async def serve_ui():
    return FileResponse(str(static_dir / "index.html"))


@app.get("/docs/quickstart")
async def serve_docs():
    return FileResponse(str(static_dir / "docs.html"))
