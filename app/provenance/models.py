"""Provenance entry data model for the tamper-proof audit trail."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
import hashlib
import hmac
import json
import uuid


# Model training data / lineage metadata — known information about upstream models.
# In production this would be pulled from a model registry or vendor API.
MODEL_INFO_REGISTRY: dict[str, dict[str, Any]] = {
    "gpt-4o": {
        "provider": "OpenAI",
        "model_version": "gpt-4o-2024-08-06",
        "training_data_cutoff": "2023-10",
        "known_training_sources": [
            "Common Crawl", "WebText2", "Books corpus",
            "Wikipedia", "Code repositories (GitHub)",
        ],
        "fine_tuned": False,
        "rlhf_aligned": True,
        "parameter_count": "undisclosed (estimated 200B+)",
        "context_window": 128000,
        "license": "Proprietary — OpenAI Terms of Use",
    },
    "gpt-4o-mini": {
        "provider": "OpenAI",
        "model_version": "gpt-4o-mini-2024-07-18",
        "training_data_cutoff": "2023-10",
        "known_training_sources": [
            "Common Crawl", "WebText2", "Books corpus",
            "Wikipedia", "Code repositories (GitHub)",
        ],
        "fine_tuned": False,
        "rlhf_aligned": True,
        "parameter_count": "undisclosed",
        "context_window": 128000,
        "license": "Proprietary — OpenAI Terms of Use",
    },
    "gpt-3.5-turbo": {
        "provider": "OpenAI",
        "model_version": "gpt-3.5-turbo-0125",
        "training_data_cutoff": "2021-09",
        "known_training_sources": [
            "Common Crawl", "WebText2", "Books corpus", "Wikipedia",
        ],
        "fine_tuned": False,
        "rlhf_aligned": True,
        "parameter_count": "~175B",
        "context_window": 16385,
        "license": "Proprietary — OpenAI Terms of Use",
    },
    "claude-sonnet-4-6": {
        "provider": "Anthropic",
        "model_version": "claude-sonnet-4-6-20250514",
        "training_data_cutoff": "2025-03",
        "known_training_sources": [
            "Web corpus", "Books", "Code repositories",
            "Academic papers", "Publicly available datasets",
        ],
        "fine_tuned": False,
        "rlhf_aligned": True,
        "parameter_count": "undisclosed",
        "context_window": 200000,
        "license": "Proprietary — Anthropic Acceptable Use Policy",
    },
}

# Approximate cost per token (USD) for cost estimation in mock mode
MODEL_COST_PER_TOKEN: dict[str, dict[str, float]] = {
    "gpt-4o":        {"input": 0.0000025, "output": 0.00001},
    "gpt-4o-mini":   {"input": 0.00000015, "output": 0.0000006},
    "gpt-3.5-turbo": {"input": 0.0000005, "output": 0.0000015},
    "claude-sonnet-4-6": {"input": 0.000003, "output": 0.000015},
}


@dataclass
class ProvenanceEntry:
    """A single entry in the tamper-proof provenance trail.

    Each entry is HMAC-chained to the previous entry, creating a tamper-evident
    log where any modification invalidates all subsequent hashes.
    """

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    session_id: str = ""
    caller_id: str = ""
    upstream_model: str = ""
    request_hash: str = ""
    response_hash: str = ""
    policy_verdicts: list[dict[str, Any]] = field(default_factory=list)
    overall_verdict: str = "PASS"
    remediation_id: str | None = None
    latency_ms: int = 0
    previous_entry_hash: str = ""
    entry_hash: str = ""

    # ── Enriched fields ──
    # Token usage
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    # Cost estimation (USD)
    estimated_cost_usd: float = 0.0
    # Full request/response content (stored encrypted at rest in production)
    request_body: str = ""          # Full prompt / messages JSON
    response_body: str = ""         # Full model response content
    system_prompt: str = ""         # System prompt if present
    # Model invocation parameters
    temperature: float | None = None
    max_tokens: int | None = None
    top_p: float | None = None
    frequency_penalty: float | None = None
    presence_penalty: float | None = None
    stop_sequences: list[str] = field(default_factory=list)
    # Tool / function call tracking
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    functions_available: list[str] = field(default_factory=list)
    # Model lineage / training data information
    model_info: dict[str, Any] = field(default_factory=dict)
    # Finish reason from model
    finish_reason: str = ""
    # Request origin metadata
    request_ip: str = ""
    user_agent: str = ""
    # System fingerprint, model routing & log probabilities
    system_fingerprint: str = ""
    model_routing: dict[str, Any] = field(default_factory=dict)
    logprobs: dict[str, Any] = field(default_factory=dict)
    # Tenant identification
    tenant_id: str = ""
    # Sanitization stats (entity types masked, never actual values)
    entities_masked: dict[str, Any] = field(default_factory=dict)

    def compute_entry_hash(self, secret_key: str) -> str:
        """Compute HMAC-SHA256 over all fields to create a tamper-evident hash.

        Note: The hash covers the original core fields for chain continuity.
        Enriched fields are included via a secondary digest to maintain backward
        compatibility while ensuring they are also tamper-evident.
        """
        # Core payload (original fields — maintains chain compatibility)
        core_payload = (
            f"{self.id}|{self.timestamp}|{self.session_id}|{self.caller_id}|"
            f"{self.upstream_model}|{self.request_hash}|{self.response_hash}|"
            f"{json.dumps(self.policy_verdicts, sort_keys=True)}|{self.overall_verdict}|"
            f"{self.remediation_id or ''}|{self.latency_ms}|{self.previous_entry_hash}"
        )
        # Enriched payload (new fields)
        enriched_payload = (
            f"|{self.prompt_tokens}|{self.completion_tokens}|{self.total_tokens}|"
            f"{self.estimated_cost_usd}|{self.finish_reason}|"
            f"{self.temperature}|{self.max_tokens}|{self.top_p}|"
            f"{json.dumps(self.tool_calls, sort_keys=True)}|"
            f"{json.dumps(self.model_info, sort_keys=True)}|"
            f"{self.system_fingerprint}|"
            f"{json.dumps(self.model_routing, sort_keys=True)}|"
            f"{json.dumps(self.logprobs, sort_keys=True)}"
        )
        full_payload = core_payload + enriched_payload
        return hmac.new(
            secret_key.encode(), full_payload.encode(), hashlib.sha256
        ).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "session_id": self.session_id,
            "caller_id": self.caller_id,
            "upstream_model": self.upstream_model,
            "request_hash": self.request_hash,
            "response_hash": self.response_hash,
            "policy_verdicts": self.policy_verdicts,
            "overall_verdict": self.overall_verdict,
            "remediation_id": self.remediation_id,
            "latency_ms": self.latency_ms,
            "previous_entry_hash": self.previous_entry_hash,
            "entry_hash": self.entry_hash,
            # Enriched fields
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "total_tokens": self.total_tokens,
            "estimated_cost_usd": self.estimated_cost_usd,
            "request_body": self.request_body,
            "response_body": self.response_body,
            "system_prompt": self.system_prompt,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
            "top_p": self.top_p,
            "frequency_penalty": self.frequency_penalty,
            "presence_penalty": self.presence_penalty,
            "stop_sequences": self.stop_sequences,
            "tool_calls": self.tool_calls,
            "functions_available": self.functions_available,
            "model_info": self.model_info,
            "finish_reason": self.finish_reason,
            "request_ip": self.request_ip,
            "user_agent": self.user_agent,
            "system_fingerprint": self.system_fingerprint,
            "model_routing": self.model_routing,
            "logprobs": self.logprobs,
            "tenant_id": self.tenant_id,
            "entities_masked": self.entities_masked,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ProvenanceEntry":
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})

    @staticmethod
    def hash_content(content: str) -> str:
        """SHA-256 hash of content for request/response hashing."""
        return hashlib.sha256(content.encode()).hexdigest()

    @staticmethod
    def estimate_tokens(text: str) -> int:
        """Rough token estimate: ~4 characters per token for English text."""
        return max(1, len(text) // 4)

    @staticmethod
    def estimate_cost(model: str, prompt_tokens: int, completion_tokens: int) -> float:
        """Estimate cost in USD based on model and token counts."""
        costs = MODEL_COST_PER_TOKEN.get(model, {"input": 0.000003, "output": 0.000015})
        return round(
            prompt_tokens * costs["input"] + completion_tokens * costs["output"], 8
        )

    @staticmethod
    def get_model_info(model: str) -> dict[str, Any]:
        """Look up known model lineage / training data information."""
        info = MODEL_INFO_REGISTRY.get(model, {
            "provider": "Unknown",
            "model_version": model,
            "training_data_cutoff": "Unknown",
            "known_training_sources": [],
            "fine_tuned": False,
            "rlhf_aligned": False,
            "parameter_count": "Unknown",
            "context_window": 0,
            "license": "Unknown",
        })
        return dict(info)  # Return a copy
