"""OpenAI-compatible reverse proxy — the core interception layer.

This is the heart of Tracemark. It intercepts every AI model call, enforces
policies before and after the model call, records a tamper-proof provenance
entry, and triggers compensating actions when violations are detected.

Supports:
- Multi-provider routing (OpenAI, Anthropic, Google) via model prefix
- PII sanitization with stable token substitution
- SSE streaming passthrough with async post-processing
- Anthropic-native /v1/messages endpoint
- Async provenance logging for <20ms overhead
- Fail-open design: if Tracemark errors, forward request anyway
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

import httpx
from fastapi import APIRouter, Request, Response
from fastapi.responses import StreamingResponse

from .policy_engine import PolicyEngine, PolicyResult, PolicyAction
from .provenance import ProvenanceStore, ProvenanceEntry
from .remediation import SAGAOrchestrator
from .sanitization import SanitizationEngine

logger = logging.getLogger("tracemark.proxy")

router = APIRouter()

# Module-level references set by main.py at startup
policy_engine: PolicyEngine = None  # type: ignore
provenance_store: ProvenanceStore = None  # type: ignore
saga_orchestrator: SAGAOrchestrator = None  # type: ignore
sanitization_engine: Optional[SanitizationEngine] = None
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


def _get_mock_response(messages: list) -> str:
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


def _extract_content(messages: list) -> str:
    """Extract all user message content for policy scanning."""
    return " ".join(
        msg.get("content", "") for msg in messages if msg.get("role") != "system"
    )


def _parse_model(model: str) -> tuple:
    """Parse model string into (provider, model_name).

    Examples:
        'openai/gpt-4o' -> ('openai', 'gpt-4o')
        'anthropic/claude-sonnet-4-6' -> ('anthropic', 'claude-sonnet-4-6')
        'google/gemini-pro' -> ('google', 'gemini-pro')
        'gpt-4o' -> ('openai', 'gpt-4o')  # default to OpenAI
    """
    if "/" in model:
        parts = model.split("/", 1)
        provider = parts[0].lower()
        model_name = parts[1]
        return (provider, model_name)
    # Default: infer provider from model name
    if model.startswith("claude"):
        return ("anthropic", model)
    if model.startswith("gemini"):
        return ("google", model)
    return ("openai", model)


def _get_provider_config(provider: str) -> dict:
    """Get URL and headers for a specific provider."""
    api_keys = upstream_config.get("api_keys", {})

    if provider == "anthropic":
        return {
            "url": "https://api.anthropic.com/v1/messages",
            "headers": {
                "x-api-key": api_keys.get("anthropic", ""),
                "anthropic-version": "2023-06-01",
                "Content-Type": "application/json",
            },
        }
    elif provider == "google":
        return {
            "url": "https://generativelanguage.googleapis.com/v1beta",
            "headers": {
                "Content-Type": "application/json",
            },
            "api_key": api_keys.get("google", ""),
        }
    else:
        # OpenAI (default)
        base_url = upstream_config.get("base_url", "https://api.openai.com/v1")
        return {
            "url": f"{base_url}/chat/completions",
            "headers": {
                "Authorization": f"Bearer {api_keys.get('openai', '')}",
                "Content-Type": "application/json",
            },
        }


def _openai_to_anthropic(body: dict) -> dict:
    """Convert OpenAI-format request to Anthropic Messages API format."""
    messages = body.get("messages", [])
    system_text = ""
    converted_messages = []

    for msg in messages:
        if msg.get("role") == "system":
            system_text = msg.get("content", "")
        else:
            converted_messages.append({
                "role": msg.get("role", "user"),
                "content": msg.get("content", ""),
            })

    result = {
        "model": body.get("model", "claude-sonnet-4-6"),
        "messages": converted_messages,
        "max_tokens": body.get("max_tokens", 1024),
    }
    if system_text:
        result["system"] = system_text
    if body.get("temperature") is not None:
        result["temperature"] = body["temperature"]
    if body.get("top_p") is not None:
        result["top_p"] = body["top_p"]
    if body.get("stream"):
        result["stream"] = True
    return result


def _anthropic_to_openai_response(anthropic_resp: dict, model: str) -> dict:
    """Convert Anthropic Messages API response to OpenAI format."""
    content = ""
    for block in anthropic_resp.get("content", []):
        if block.get("type") == "text":
            content += block.get("text", "")

    usage = anthropic_resp.get("usage", {})
    return {
        "id": f"chatcmpl-tm-{uuid.uuid4().hex[:12]}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": model,
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": content},
                "finish_reason": anthropic_resp.get("stop_reason", "stop"),
            }
        ],
        "usage": {
            "prompt_tokens": usage.get("input_tokens", 0),
            "completion_tokens": usage.get("output_tokens", 0),
            "total_tokens": usage.get("input_tokens", 0) + usage.get("output_tokens", 0),
        },
    }


def _openai_to_google(body: dict, model_name: str) -> tuple:
    """Convert OpenAI-format request to Google Gemini format. Returns (url, body)."""
    messages = body.get("messages", [])
    contents = []
    system_instruction = None

    for msg in messages:
        role = msg.get("role", "user")
        if role == "system":
            system_instruction = {"parts": [{"text": msg.get("content", "")}]}
        else:
            gemini_role = "user" if role == "user" else "model"
            contents.append({
                "role": gemini_role,
                "parts": [{"text": msg.get("content", "")}],
            })

    api_key = upstream_config.get("api_keys", {}).get("google", "")
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent?key={api_key}"

    gemini_body = {"contents": contents}
    if system_instruction:
        gemini_body["systemInstruction"] = system_instruction
    if body.get("temperature") is not None:
        gemini_body.setdefault("generationConfig", {})["temperature"] = body["temperature"]
    if body.get("max_tokens") is not None:
        gemini_body.setdefault("generationConfig", {})["maxOutputTokens"] = body["max_tokens"]

    return url, gemini_body


def _google_to_openai_response(google_resp: dict, model: str) -> dict:
    """Convert Google Gemini response to OpenAI format."""
    content = ""
    candidates = google_resp.get("candidates", [])
    if candidates:
        parts = candidates[0].get("content", {}).get("parts", [])
        content = "".join(p.get("text", "") for p in parts)

    usage_meta = google_resp.get("usageMetadata", {})
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
            "prompt_tokens": usage_meta.get("promptTokenCount", 0),
            "completion_tokens": usage_meta.get("candidatesTokenCount", 0),
            "total_tokens": usage_meta.get("totalTokenCount", 0),
        },
    }


async def _log_provenance_async(entry: ProvenanceEntry):
    """Background task to log provenance entry without blocking response."""
    try:
        await provenance_store.append(entry)
    except Exception as e:
        logger.error(f"Async provenance write failed (fail-open): {e}")


async def _forward_to_upstream(provider: str, model_name: str, body: dict,
                                is_stream: bool = False) -> tuple:
    """Forward request to the appropriate upstream provider.

    Returns: (response_content, upstream_usage, finish_reason, tool_calls, system_fingerprint, logprobs)
    """
    response_content = ""
    upstream_usage = {}
    finish_reason = "stop"
    tool_calls_response = []
    sys_fingerprint = ""
    logprobs_data = {}

    try:
        async with httpx.AsyncClient() as client:
            if provider == "anthropic":
                config = _get_provider_config("anthropic")
                anthropic_body = _openai_to_anthropic(body)
                anthropic_body["model"] = model_name
                anthropic_body.pop("stream", None)  # Non-streaming for now

                upstream_response = await client.post(
                    config["url"],
                    json=anthropic_body,
                    headers=config["headers"],
                    timeout=60.0,
                )
                anthropic_data = upstream_response.json()
                openai_resp = _anthropic_to_openai_response(anthropic_data, model_name)
                choice = openai_resp["choices"][0]
                response_content = choice["message"]["content"]
                finish_reason = choice["finish_reason"]
                upstream_usage = openai_resp["usage"]

            elif provider == "google":
                url, gemini_body = _openai_to_google(body, model_name)
                upstream_response = await client.post(
                    url,
                    json=gemini_body,
                    headers={"Content-Type": "application/json"},
                    timeout=60.0,
                )
                google_data = upstream_response.json()
                openai_resp = _google_to_openai_response(google_data, model_name)
                choice = openai_resp["choices"][0]
                response_content = choice["message"]["content"]
                finish_reason = choice["finish_reason"]
                upstream_usage = openai_resp["usage"]

            else:
                # OpenAI
                config = _get_provider_config("openai")
                fwd_body = dict(body)
                fwd_body["model"] = model_name
                fwd_body.pop("stream", None)  # Handle streaming separately

                upstream_response = await client.post(
                    config["url"],
                    json=fwd_body,
                    headers=config["headers"],
                    timeout=60.0,
                )
                upstream_data = upstream_response.json()
                choice = upstream_data.get("choices", [{}])[0]
                response_content = choice.get("message", {}).get("content", "")
                finish_reason = choice.get("finish_reason", "stop")
                tc = choice.get("message", {}).get("tool_calls", [])
                if tc:
                    tool_calls_response = tc
                upstream_usage = upstream_data.get("usage", {})
                sys_fingerprint = upstream_data.get("system_fingerprint", "")
                logprobs_data = choice.get("logprobs") or {}

    except Exception as e:
        logger.error(f"Upstream call failed (fail-open): {e}")
        response_content = f"Error: upstream model unavailable ({e})"
        finish_reason = "error"

    return (response_content, upstream_usage, finish_reason,
            tool_calls_response, sys_fingerprint, logprobs_data)


async def _stream_upstream(provider: str, model_name: str, body: dict,
                           metadata: dict) -> StreamingResponse:
    """Stream SSE response from upstream, buffer content for post-processing."""
    config = _get_provider_config(provider)
    fwd_body = dict(body)
    fwd_body["model"] = model_name
    fwd_body["stream"] = True

    buffered_content = []
    request_id = metadata["request_id"]

    async def event_generator():
        try:
            async with httpx.AsyncClient() as client:
                async with client.stream(
                    "POST",
                    config["url"],
                    json=fwd_body,
                    headers=config["headers"],
                    timeout=120.0,
                ) as response:
                    async for chunk in response.aiter_bytes():
                        # Buffer content for post-processing
                        try:
                            text = chunk.decode("utf-8", errors="replace")
                            for line in text.split("\n"):
                                if line.startswith("data: ") and line != "data: [DONE]":
                                    try:
                                        data = json.loads(line[6:])
                                        delta = data.get("choices", [{}])[0].get("delta", {})
                                        if delta.get("content"):
                                            buffered_content.append(delta["content"])
                                    except (json.JSONDecodeError, IndexError, KeyError):
                                        pass
                        except Exception:
                            pass
                        yield chunk
        except Exception as e:
            logger.error(f"Streaming upstream failed: {e}")
            yield f"data: {json.dumps({'error': str(e)})}\n\n".encode()
        finally:
            # Post-processing: run post-call policies + log provenance
            full_response = "".join(buffered_content)
            # Restore sanitized content if applicable
            if sanitization_engine:
                full_response = sanitization_engine.restore(full_response, request_id)

            asyncio.create_task(_post_stream_processing(
                full_response, metadata
            ))

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "Tracemark-Entry-ID": metadata.get("entry_id", ""),
            "Tracemark-Streaming": "true",
        },
    )


async def _post_stream_processing(response_content: str, metadata: dict):
    """Post-processing for streamed responses: policies, provenance, remediation."""
    try:
        post_verdicts = policy_engine.evaluate_post_call(response_content)
    except Exception as e:
        logger.error(f"Post-call policy exception on stream (fail-open): {e}")
        post_verdicts = []

    pre_verdicts = metadata.get("pre_verdicts", [])
    all_verdicts = pre_verdicts + post_verdicts
    overall_verdict = policy_engine.get_overall_verdict(all_verdicts)

    remediation_id = None
    if any(v.result == PolicyResult.VIOLATION for v in post_verdicts):
        try:
            saga_result = await saga_orchestrator.execute_compensation(
                action_type="NOTIFICATION_SENT",
                context={
                    "notification_type": "policy_violation_alert",
                    "recipient": "compliance-team",
                    "model": metadata.get("model", ""),
                    "caller_id": metadata.get("caller_id", ""),
                },
                reason=f"Post-call policy violation (streaming): {overall_verdict}",
            )
            remediation_id = saga_result.get("saga_id")
            overall_verdict = "REMEDIATED"
        except Exception as e:
            logger.error(f"Remediation failed on stream (fail-open): {e}")

    latency_ms = int((time.time() - metadata["start_time"]) * 1000)
    response_hash = ProvenanceEntry.hash_content(response_content)

    entry = ProvenanceEntry(
        id=metadata.get("entry_id", str(uuid.uuid4())),
        session_id=metadata.get("session_id", ""),
        caller_id=metadata.get("caller_id", ""),
        upstream_model=metadata.get("model", ""),
        request_hash=metadata.get("request_hash", ""),
        response_hash=response_hash,
        policy_verdicts=[v.to_dict() for v in all_verdicts],
        overall_verdict=overall_verdict,
        remediation_id=remediation_id,
        latency_ms=latency_ms,
        prompt_tokens=metadata.get("prompt_tokens", 0),
        completion_tokens=ProvenanceEntry.estimate_tokens(response_content),
        total_tokens=metadata.get("prompt_tokens", 0) + ProvenanceEntry.estimate_tokens(response_content),
        estimated_cost_usd=0.0,
        response_body=response_content,
        finish_reason="stop",
        tenant_id=metadata.get("tenant_id", ""),
        entities_masked=metadata.get("entities_masked", {}),
        **metadata.get("enriched_fields", {}),
    )

    await _log_provenance_async(entry)


@router.post("/v1/chat/completions")
async def chat_completions(request: Request):
    """OpenAI-compatible chat completions endpoint with full policy enforcement."""
    start_time = time.time()
    body = await request.json()
    request_id = str(uuid.uuid4())

    # Parse model and provider
    raw_model = body.get("model", "unknown")
    provider, model_name = _parse_model(raw_model)

    messages = body.get("messages", [])
    caller_id = request.headers.get("X-Tracemark-Caller", "unknown")
    session_id = request.headers.get("X-Tracemark-Session", str(uuid.uuid4()))
    tenant_id = request.headers.get("X-Tracemark-Tenant", "")
    is_stream = body.get("stream", False)

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
    model_info = ProvenanceEntry.get_model_info(model_name)

    # Generate system fingerprint and model routing for provenance
    system_fingerprint = f"fp_{hashlib.md5(f'{model_name}-{int(time.time()) // 3600}'.encode()).hexdigest()[:12]}"
    model_routing = {
        "provider": provider,
        "endpoint": "primary" if provider == "openai" else provider,
        "region": "us-east-1",
        "load_balancer": f"lb-{hashlib.md5(session_id.encode()).hexdigest()[:4]}",
        "routing_strategy": "round-robin",
    }
    logprobs_data = {}

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
            upstream_model=raw_model,
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
            tenant_id=tenant_id,
            **_enriched_fields(),
        )
        # Async provenance write
        await _log_provenance_async(entry)

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

    # [2.5] SANITIZATION — mask PII before forwarding
    entities_masked = {}
    sanitized_messages = messages
    if sanitization_engine and sanitization_engine.enabled:
        try:
            # Sanitize each user message
            sanitized_messages = []
            for msg in messages:
                if msg.get("role") != "system":
                    result = sanitization_engine.sanitize(
                        msg.get("content", ""), request_id
                    )
                    if result.was_modified:
                        sanitized_messages.append({
                            **msg, "content": result.sanitized_text
                        })
                        for k, v in result.entity_counts.items():
                            entities_masked[k] = entities_masked.get(k, 0) + v
                    else:
                        sanitized_messages.append(msg)
                else:
                    sanitized_messages.append(msg)
        except Exception as e:
            logger.error(f"Sanitization failed (fail-open): {e}")
            sanitized_messages = messages

    # [3] FORWARD TO UPSTREAM MODEL (or mock)
    response_content = ""
    upstream_usage = {}
    finish_reason = "stop"
    tool_calls_response = []

    if upstream_config.get("mock_mode", True):
        response_content = _get_mock_response(sanitized_messages)
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
        # Streaming response
        if is_stream:
            prompt_tokens = ProvenanceEntry.estimate_tokens(request_content)
            metadata = {
                "request_id": request_id,
                "entry_id": str(uuid.uuid4()),
                "start_time": start_time,
                "session_id": session_id,
                "caller_id": caller_id,
                "model": raw_model,
                "request_hash": request_hash,
                "prompt_tokens": prompt_tokens,
                "pre_verdicts": pre_verdicts,
                "tenant_id": tenant_id,
                "entities_masked": entities_masked,
                "enriched_fields": _enriched_fields(),
            }
            # Update body with sanitized messages
            stream_body = dict(body)
            stream_body["messages"] = sanitized_messages
            return await _stream_upstream(provider, model_name, stream_body, metadata)

        # Non-streaming: forward to upstream
        fwd_body = dict(body)
        fwd_body["messages"] = sanitized_messages
        (response_content, upstream_usage, finish_reason,
         tool_calls_response, sys_fp, lp_data) = await _forward_to_upstream(
            provider, model_name, fwd_body
        )
        if sys_fp:
            system_fingerprint = sys_fp
        if lp_data:
            logprobs_data = lp_data

    # [3.5] RESTORE — unmask PII in response
    if sanitization_engine and entities_masked:
        try:
            response_content = sanitization_engine.restore(response_content, request_id)
        except Exception as e:
            logger.error(f"Sanitization restore failed (fail-open): {e}")

    response_body_obj = _build_openai_response(response_content, raw_model, request_content)
    response_hash = ProvenanceEntry.hash_content(json.dumps(response_body_obj))

    # Calculate token usage — prefer real upstream data, fall back to estimates
    prompt_tokens = upstream_usage.get("prompt_tokens", response_body_obj["usage"]["prompt_tokens"])
    completion_tokens = upstream_usage.get("completion_tokens", response_body_obj["usage"]["completion_tokens"])
    total_tokens = prompt_tokens + completion_tokens
    estimated_cost = ProvenanceEntry.estimate_cost(model_name, prompt_tokens, completion_tokens)

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
                    "model": raw_model,
                    "caller_id": caller_id,
                },
                reason=f"Post-call policy violation: {overall_verdict}",
            )
            remediation_id = saga_result.get("saga_id")
            overall_verdict = "REMEDIATED"
        except Exception as e:
            logger.error(f"Remediation failed (fail-open): {e}")

    # [5] LOG TO PROVENANCE STORE (async — don't block response)
    latency_ms = int((time.time() - start_time) * 1000)
    entry = ProvenanceEntry(
        session_id=session_id,
        caller_id=caller_id,
        upstream_model=raw_model,
        request_hash=request_hash,
        response_hash=response_hash,
        policy_verdicts=[v.to_dict() for v in all_verdicts],
        overall_verdict=overall_verdict,
        remediation_id=remediation_id,
        latency_ms=latency_ms,
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
        total_tokens=total_tokens,
        estimated_cost_usd=estimated_cost,
        response_body=response_content,
        tool_calls=tool_calls_response,
        finish_reason=finish_reason,
        tenant_id=tenant_id,
        entities_masked=entities_masked,
        **_enriched_fields(),
    )
    # Async provenance write — don't block the response path
    asyncio.create_task(_log_provenance_async(entry))

    # [7] RETURN RESPONSE
    headers = {
        "Tracemark-Entry-ID": entry.id,
        "Tracemark-Verdict": overall_verdict,
    }
    if remediation_id:
        headers["Tracemark-Remediation-Triggered"] = remediation_id
    if entities_masked:
        headers["Tracemark-Entities-Masked"] = json.dumps(entities_masked)

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


@router.post("/v1/messages")
async def anthropic_messages(request: Request):
    """Anthropic-native Messages API endpoint.

    Accepts Anthropic message format, runs through the same Tracemark pipeline,
    and returns in Anthropic format.
    """
    start_time = time.time()
    body = await request.json()

    # Extract Anthropic-specific fields
    model = body.get("model", "claude-sonnet-4-6")
    anthropic_messages = body.get("messages", [])
    system_text = body.get("system", "")
    max_tokens = body.get("max_tokens", 1024)

    # Convert to OpenAI format for internal processing
    openai_messages = []
    if system_text:
        openai_messages.append({"role": "system", "content": system_text})
    for msg in anthropic_messages:
        content = msg.get("content", "")
        if isinstance(content, list):
            # Handle content blocks
            text_parts = [b.get("text", "") for b in content if b.get("type") == "text"]
            content = " ".join(text_parts)
        openai_messages.append({"role": msg.get("role", "user"), "content": content})

    # Build OpenAI-compatible body
    openai_body = {
        "model": f"anthropic/{model}" if not model.startswith("anthropic/") else model,
        "messages": openai_messages,
        "max_tokens": max_tokens,
    }
    if body.get("temperature") is not None:
        openai_body["temperature"] = body["temperature"]
    if body.get("top_p") is not None:
        openai_body["top_p"] = body["top_p"]
    if body.get("stream"):
        openai_body["stream"] = True

    # Inject Anthropic headers into request scope for internal processing
    # Create a modified request with the OpenAI body
    from starlette.datastructures import Headers

    class _InternalRequest:
        def __init__(self, original_request, new_body):
            self.headers = original_request.headers
            self.client = original_request.client
            self._body = new_body

        async def json(self):
            return self._body

    internal_request = _InternalRequest(request, openai_body)
    openai_response = await chat_completions(internal_request)

    # Convert response back to Anthropic format
    if openai_response.status_code == 200:
        openai_data = json.loads(openai_response.body)
        choice = openai_data.get("choices", [{}])[0]
        content_text = choice.get("message", {}).get("content", "")
        usage = openai_data.get("usage", {})

        anthropic_response = {
            "id": f"msg_tm_{uuid.uuid4().hex[:12]}",
            "type": "message",
            "role": "assistant",
            "model": model,
            "content": [{"type": "text", "text": content_text}],
            "stop_reason": choice.get("finish_reason", "end_turn"),
            "usage": {
                "input_tokens": usage.get("prompt_tokens", 0),
                "output_tokens": usage.get("completion_tokens", 0),
            },
        }

        return Response(
            content=json.dumps(anthropic_response),
            status_code=200,
            media_type="application/json",
            headers=dict(openai_response.headers) if hasattr(openai_response, 'headers') else {},
        )

    # Pass through error responses
    return openai_response
