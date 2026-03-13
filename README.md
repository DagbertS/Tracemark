# Tracemark

**AI governance, control, and remediation infrastructure.** Tracemark is the enforcement layer that sits between enterprise systems and AI models — intercepting every call, enforcing policy rules in real time, recording a tamper-proof provenance trail, and executing compensating transactions when AI decisions produce unintended effects.

Think of it as: databases have ACID transactions. Networks have firewalls. Tracemark gives the same guarantees to AI systems.

## Quick Start

```bash
# Run with Docker Compose
docker-compose up --build

# In another terminal, run the demo
chmod +x demo.sh
./demo.sh

# Open the dashboard
open http://localhost:8080
```

Or run locally without Docker:

```bash
pip install -r requirements.txt
uvicorn app.main:app --port 8080
./demo.sh
```

## Architecture

```
Enterprise App
     |
     v  POST /v1/chat/completions
+--------------------------------------------------+
|              TRACEMARK PROXY                      |
|                                                   |
|  [1] REQUEST INTERCEPTED                          |
|  [2] PRE-CALL POLICY SCAN (PII, blocklist)        |
|  [3] FORWARD TO UPSTREAM MODEL (or mock)          |
|  [4] POST-CALL POLICY SCAN (confidence, PII)      |
|  [5] LOG TO PROVENANCE STORE (HMAC-chained)       |
|  [6] REMEDIATION ENGINE (if violation detected)   |
|  [7] RETURN RESPONSE (with Tracemark headers)     |
+--------------------------------------------------+
```

The proxy exposes an OpenAI-compatible endpoint. Any existing LLM client works without code changes — just point it at Tracemark.

## Configuring Policies

All policies are defined in `config.yaml`. Three built-in policy types:

- **PII Detection**: regex-based scanning for emails, phone numbers, credit cards
- **Topic Blocklist**: forbidden topic string matching
- **Confidence Threshold**: flags responses containing uncertainty language

### Adding a New Policy Type

1. Create a new class in `app/policy_engine/` extending `BasePolicy`
2. Implement the `evaluate(content: str) -> PolicyVerdict` method
3. Register it in `POLICY_CLASS_MAP` in `engine.py` and add config to `config.yaml`

## Registering Compensating Actions

The SAGA remediation engine maps AI action types to compensating transactions.

### Adding a New Compensating Action

1. Create an async function in `app/remediation/actions/` that takes a context dict and returns a result dict
2. Add the action type mapping to the `action_registry` section of `config.yaml`
3. The function is automatically registered at startup via `build_action_registry()` in `main.py`

## Provenance Chain

Every intercepted call produces a provenance entry with an HMAC-SHA256 hash. Each entry includes the hash of the previous entry, creating a tamper-evident chain. Modifying any historical entry invalidates all subsequent hashes.

Verify chain integrity:

```bash
curl http://localhost:8080/api/provenance/verify
```

## API Reference

### Proxy

```bash
# OpenAI-compatible chat completions (the interception point)
curl -X POST http://localhost:8080/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "X-Tracemark-Caller: my-app" \
  -H "X-Tracemark-Session: session-001" \
  -d '{"model": "gpt-4o", "messages": [{"role": "user", "content": "Hello"}]}'
```

### Provenance

```bash
# List entries
curl http://localhost:8080/api/provenance?limit=20

# Get single entry
curl http://localhost:8080/api/provenance/{entry-id}

# Verify chain integrity
curl http://localhost:8080/api/provenance/verify

# Get stats
curl http://localhost:8080/api/provenance/stats
```

### Policies

```bash
# List active policies
curl http://localhost:8080/api/policies
```

### Remediation

```bash
# Trigger manual remediation
curl -X POST http://localhost:8080/api/remediate \
  -H "Content-Type: application/json" \
  -d '{"action_type": "EMAIL_SENT", "context": {"recipient": "a@b.com"}, "reason": "Policy violation"}'

# View SAGA execution log
curl http://localhost:8080/api/remediation/log

# View action registry
curl http://localhost:8080/api/remediation/registry
```

### Health

```bash
curl http://localhost:8080/health
```

## Running Tests

```bash
pytest tests/ -v
```

## Configuration

All configuration is in `config.yaml`. The secret key for HMAC signing can be overridden via the `TRACEMARK_SECRET_KEY` environment variable. Set `upstream.mock_mode: false` and provide `OPENAI_API_KEY` to use a real model provider.
