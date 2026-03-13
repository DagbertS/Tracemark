"""OpenAI-compatible reverse proxy — the core interception layer.

This is the heart of Tracemark. It intercepts every AI model call, enforces
policies before and after the model call, records a tamper-proof provenance
entry, and triggers compensating actions when violations are detected.

TODO: Add ToolCallInterceptor hook here for MCP/tool-call-level interception (Phase 2).
      The pipeline architecture supports inserting an additional interceptor between
      steps [3] and [4] that would inspect individual tool calls within the model response.

TODO: Add streaming (SSE) response support. The current implementation handles
      non-streaming responses only. For streaming, buffer chunks, run post-call
      policies on the assembled response, and re-stream to the caller.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Any

import httpx
from fastapi import APIRouter, Request, Response

from .policy_engine import PolicyEngine, PolicyResult, PolicyAction
from .provenance import ProvenanceStore, ProvenanceEntry
from .remediation import SAGAOrchestrator

logger = logging.getLogger("tracemark.proxy")

router = APIRouter()

# Module-level references set by main.py at startup
policy_engine: PolicyEngine = None  # type: ignore
provenance_store: ProvenanceStore = None  # type: ignore
saga_orchestrator: SAGAOrchestrator = None  # type: ignore
upstream_config: dict[str, Any] = {}

# Mock responses for demo mode — each triggers different policy outcomes
MOCK_RESPONSES = [
    {
        "trigger": "default",
        "content": "Here is a summary of the Q3 product roadmap: We are focusing on three key areas — enterprise integration improvements, enhanced analytics dashboards, and expanded API capabilities. The team has completed 60% of planned deliverables and is on track for the September release.",
    },
    {
        "trigger": "pii_response",
        "content": "I found the customer record. The account holder is John Smith, reachable at john.smith@acmecorp.com or (555) 123-4567. Their credit card on file ends in 4242.",
    },
    {
        "trigger": "forbidden_topic",
        "content": "Based on my analysis, the competitor pricing for similar enterprise SaaS tools ranges from $50k to $200k ARR. I would recommend positioning below their entry tier.",
    },
    {
        "trigger": "uncertainty",
        "content": "Regarding the investment decision, I am not sure this is the right time to proceed. You should consult with a qualified financial advisor before making any commitments. I may be wrong about the market conditions.",
    },
    {
        "trigger": "remediation",
        "content": "I have sent the promotional email to the customer at the address provided. The CRM record has been updated with the new contact preferences. A notification was sent to the sales team about the account change.",
    },
]


def _get_mock_response(messages: list[dict]) -> str:
    """Select an appropriate mock response based on the prompt content."""
    if not messages:
        return MOCK_RESPONSES[0]["content"]

    last_message = messages[-1].get("content", "").lower()

    if "investment" in last_message or "proceed" in last_message:
        return MOCK_RESPONSES[3]["content"]
    if "competitor" in last_message or "pricing" in last_message:
        return MOCK_RESPONSES[2]["content"]
    if "email" in last_message and ("@" in last_message or "customer" in last_message):
        return MOCK_RESPONSES[1]["content"]
    if "send" in last_message or "update crm" in last_message:
        return MOCK_RESPONSES[4]["content"]

    return MOCK_RESPONSES[0]["content"]


def _build_openai_response(content: str, model: str, prompt_text: str = "") -> dict:
    """Build an OpenAI-format chat completion response with realistic token counts."""
    prompt_tokens = ProvenanceEntry.estimate_tokens(prompt_text) if prompt_text else 0
    completion_tokens = ProvenanceEntry.estimate_tokens(content)
    return {
        "id": f"chatcmpl-tm-{uuid.uuid4().hex[:12]}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": model,
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": content},
                "finish_reason": "stop",
            }
        ],
        "usage": {
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": prompt_tokens + completion_tokens,
        },
    }


def _extract_content(messages: list[dict]) -> str:
    """Extract all user message content for policy scanning."""
    return " ".join(
        msg.get("content", "") for msg in messages if msg.get("role") != "system"
    )


@router.post("/v1/chat/completions")
async def chat_completions(request: Request):
    """OpenAI-compatible chat completions endpoint with full policy enforcement."""
    start_time = time.time()
    body = await request.json()

    model = body.get("model", "unknown")
    messages = body.get("messages", [])
    caller_id = request.headers.get("X-Tracemark-Caller", "unknown")
    session_id = request.headers.get("X-Tracemark-Session", str(uuid.uuid4()))

    # Extract request origin metadata
    request_ip = request.headers.get("X-Forwarded-For", request.client.host if request.client else "unknown")
    user_agent = request.headers.get("User-Agent", "unknown")

    # Extract model invocation parameters
    temperature = body.get("temperature")
    max_tokens_param = body.get("max_tokens")
    top_p = body.get("top_p")
    frequency_penalty = body.get("frequency_penalty")
    presence_penalty = body.get("presence_penalty")
    stop_sequences = body.get("stop", [])
    if isinstance(stop_sequences, str):
        stop_sequences = [stop_sequences]

    # Extract system prompt if present
    system_prompt = ""
    for msg in messages:
        if msg.get("role") == "system":
            system_prompt = msg.get("content", "")
            break

    # Extract tool/function definitions
    tools = body.get("tools", [])
    functions = body.get("functions", [])
    functions_available = [t.get("function", {}).get("name", "") for t in tools if t.get("function")]
    if functions:
        functions_available += [f.get("name", "") for f in functions]

    request_content = _extract_content(messages)
    request_hash = ProvenanceEntry.hash_content(json.dumps(body))

    # Look up model lineage / training data information
    model_info = ProvenanceEntry.get_model_info(model)

    # Generate system fingerprint and model routing for provenance
    system_fingerprint = f"fp_{hashlib.md5(f'{model}-{int(time.time()) // 3600}'.encode()).hexdigest()[:12]}"
    model_routing = {
        "endpoint": "primary" if "gpt" in model else "anthropic",
        "region": "us-east-1",
        "load_balancer": f"lb-{hashlib.md5(session_id.encode()).hexdigest()[:4]}",
        "routing_strategy": "round-robin",
    }
    logprobs_data: dict = {}

    # Common enriched fields for all provenance entries in this request
    def _enriched_fields(**overrides):
        base = dict(
            request_body=json.dumps(messages),
            system_prompt=system_prompt,
            temperature=temperature,
            max_tokens=max_tokens_param,
            top_p=top_p,
            frequency_penalty=frequency_penalty,
            presence_penalty=presence_penalty,
            stop_sequences=stop_sequences or [],
            functions_available=functions_available,
            model_info=model_info,
            request_ip=request_ip,
            user_agent=user_agent,
            system_fingerprint=system_fingerprint,
            model_routing=model_routing,
            logprobs=logprobs_data,
        )
        base.update(overrides)
        return base

    # [2] PRE-CALL POLICY SCAN
    try:
        pre_verdicts = policy_engine.evaluate_pre_call(request_content)
    except Exception as e:
        logger.error(f"Policy engine pre-call exception (fail-open): {e}")
        pre_verdicts = []

    if policy_engine.has_blocking_violation(pre_verdicts):
        # Request blocked — log and return 403
        latency_ms = int((time.time() - start_time) * 1000)
        prompt_tokens = ProvenanceEntry.estimate_tokens(request_content)
        entry = ProvenanceEntry(
            session_id=session_id,
            caller_id=caller_id,
            upstream_model=model,
            request_hash=request_hash,
            response_hash="",
            policy_verdicts=[v.to_dict() for v in pre_verdicts],
            overall_verdict="BLOCKED",
            latency_ms=latency_ms,
            prompt_tokens=prompt_tokens,
            completion_tokens=0,
            total_tokens=prompt_tokens,
            estimated_cost_usd=0.0,
            response_body="",
            finish_reason="policy_blocked",
            **_enriched_fields(),
        )
        try:
            await provenance_store.append(entry)
        except Exception as e:
            logger.error(f"Provenance write failed (fail-open): {e}")

        violation_details = [
            v.to_dict() for v in pre_verdicts if v.result == PolicyResult.VIOLATION
        ]
        return Response(
            content=json.dumps({
                "error": {
                    "message": "Request blocked by Tracemark policy enforcement",
                    "type": "policy_violation",
                    "violations": violation_details,
                }
            }),
            status_code=403,
            media_type="application/json",
            headers={
                "Tracemark-Entry-ID": entry.id,
                "Tracemark-Verdict": "BLOCKED",
                "Tracemark-Policy-Violation": "true",
            },
        )

    # [3] FORWARD TO UPSTREAM MODEL (or mock)
    response_content = ""
    upstream_usage = {}
    finish_reason = "stop"
    tool_calls_response = []

    if upstream_config.get("mock_mode", True):
        response_content = _get_mock_response(messages)
        # Generate mock logprobs for demo purposes
        import random
        words = response_content.split()[:5]
        logprobs_data = {
            "tokens": words,
            "token_logprobs": [round(random.uniform(-2.0, -0.01), 4) for _ in words],
            "top_logprobs": [
                {w: round(random.uniform(-2.0, -0.01), 4)} for w in words
            ],
        }
    else:
        try:
            async with httpx.AsyncClient() as client:
                upstream_response = await client.post(
                    f"{upstream_config['base_url']}/chat/completions",
                    json=body,
                    headers={
                        "Authorization": f"Bearer {upstream_config.get('api_key', '')}",
                        "Content-Type": "application/json",
                    },
                    timeout=60.0,
                )
                upstream_data = upstream_response.json()
                choice = upstream_data.get("choices", [{}])[0]
                response_content = choice.get("message", {}).get("content", "")
                finish_reason = choice.get("finish_reason", "stop")
                # Capture tool calls from the response
                tc = choice.get("message", {}).get("tool_calls", [])
                if tc:
                    tool_calls_response = tc
                # Capture real token usage from upstream
                upstream_usage = upstream_data.get("usage", {})
                # Extract system fingerprint and logprobs from upstream
                system_fingerprint = upstream_data.get("system_fingerprint", system_fingerprint)
                logprobs_data = choice.get("logprobs") or {}
        except Exception as e:
            logger.error(f"Upstream call failed (fail-open): {e}")
            response_content = f"Error: upstream model unavailable ({e})"
            finish_reason = "error"

    response_body_obj = _build_openai_response(response_content, model, request_content)
    response_hash = ProvenanceEntry.hash_content(json.dumps(response_body_obj))

    # Calculate token usage — prefer real upstream data, fall back to estimates
    prompt_tokens = upstream_usage.get("prompt_tokens", response_body_obj["usage"]["prompt_tokens"])
    completion_tokens = upstream_usage.get("completion_tokens", response_body_obj["usage"]["completion_tokens"])
    total_tokens = prompt_tokens + completion_tokens
    estimated_cost = ProvenanceEntry.estimate_cost(model, prompt_tokens, completion_tokens)

    # Update the response body with accurate token counts
    response_body_obj["usage"] = {
        "prompt_tokens": prompt_tokens,
        "completion_tokens": completion_tokens,
        "total_tokens": total_tokens,
    }

    # [4] POST-CALL POLICY SCAN
    try:
        post_verdicts = policy_engine.evaluate_post_call(response_content)
    except Exception as e:
        logger.error(f"Policy engine post-call exception (fail-open): {e}")
        post_verdicts = []

    all_verdicts = pre_verdicts + post_verdicts
    overall_verdict = policy_engine.get_overall_verdict(all_verdicts)

    # [6] REMEDIATION if violation detected on response
    remediation_id = None
    if any(v.result == PolicyResult.VIOLATION for v in post_verdicts):
        try:
            saga_result = await saga_orchestrator.execute_compensation(
                action_type="NOTIFICATION_SENT",
                context={
                    "notification_type": "policy_violation_alert",
                    "recipient": "compliance-team",
                    "model": model,
                    "caller_id": caller_id,
                },
                reason=f"Post-call policy violation: {overall_verdict}",
            )
            remediation_id = saga_result.get("saga_id")
            overall_verdict = "REMEDIATED"
        except Exception as e:
            logger.error(f"Remediation failed (fail-open): {e}")

    # [5] LOG TO PROVENANCE STORE
    latency_ms = int((time.time() - start_time) * 1000)
    entry = ProvenanceEntry(
        session_id=session_id,
        caller_id=caller_id,
        upstream_model=model,
        request_hash=request_hash,
        response_hash=response_hash,
        policy_verdicts=[v.to_dict() for v in all_verdicts],
        overall_verdict=overall_verdict,
        remediation_id=remediation_id,
        latency_ms=latency_ms,
        # Enriched fields
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
        total_tokens=total_tokens,
        estimated_cost_usd=estimated_cost,
        response_body=response_content,
        tool_calls=tool_calls_response,
        finish_reason=finish_reason,
        **_enriched_fields(),
    )
    try:
        await provenance_store.append(entry)
    except Exception as e:
        logger.error(f"Provenance write failed (fail-open): {e}")

    # [7] RETURN RESPONSE
    headers = {
        "Tracemark-Entry-ID": entry.id,
        "Tracemark-Verdict": overall_verdict,
    }
    if remediation_id:
        headers["Tracemark-Remediation-Triggered"] = remediation_id

    # If post-call found a blocking violation, block the response
    if policy_engine.has_blocking_violation(post_verdicts):
        violation_details = [
            v.to_dict() for v in post_verdicts if v.result == PolicyResult.VIOLATION
        ]
        return Response(
            content=json.dumps({
                "error": {
                    "message": "Response blocked by Tracemark policy enforcement",
                    "type": "policy_violation",
                    "violations": violation_details,
                }
            }),
            status_code=403,
            media_type="application/json",
            headers={**headers, "Tracemark-Policy-Violation": "true"},
        )

    return Response(
        content=json.dumps(response_body_obj),
        status_code=200,
        media_type="application/json",
        headers=headers,
    )
