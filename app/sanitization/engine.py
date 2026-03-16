"""Sanitization Engine — PII detection, stable-token substitution, and restoration.

Sits in the proxy pipeline between pre-call policy and upstream forwarding.
Detects PII entities, replaces them with stable tokens like [EMAIL_a3f2],
stores the mapping in the vault, and reverses substitution in the response.
"""

from __future__ import annotations

import hashlib
import logging
import re
from dataclasses import dataclass, field
from typing import Optional

from .patterns import PII_PATTERNS, COMMON_FALSE_POSITIVES
from .vault import VaultStore

logger = logging.getLogger("tracemark.sanitization")


@dataclass
class SanitizeResult:
    """Result of a sanitization pass."""
    sanitized_text: str
    entity_counts: dict  # {entity_type: count} — never contains actual values
    was_modified: bool
    request_id: str = ""


class SanitizationEngine:
    """Orchestrates PII detection, substitution, and restoration.

    Usage:
        engine = SanitizationEngine(vault)
        result = engine.sanitize(text, request_id)
        # ... forward result.sanitized_text to model ...
        restored = engine.restore(model_response, request_id)
    """

    def __init__(self, vault: VaultStore, enabled: bool = True):
        self.vault = vault
        self.enabled = enabled

    def sanitize(self, text: str, request_id: str) -> SanitizeResult:
        """Detect PII in text and replace with stable tokens.

        Each unique PII value maps to a deterministic token like [EMAIL_a3f2].
        The same value always produces the same token within a request.
        """
        if not self.enabled or not text:
            return SanitizeResult(
                sanitized_text=text,
                entity_counts={},
                was_modified=False,
                request_id=request_id,
            )

        mappings = {}  # token → original
        entity_counts = {}  # type → count
        sanitized = text

        for pattern_name, regex, validator in PII_PATTERNS:
            matches = list(regex.finditer(sanitized))
            for match in reversed(matches):  # reverse to preserve indices
                value = match.group(0).strip()

                # Skip empty or too-short matches
                if len(value) < 3:
                    continue

                # Run validator if present
                if validator is not None:
                    try:
                        if not validator(value):
                            continue
                    except Exception:
                        continue

                # Skip known false positives for names
                if pattern_name == "name" and value in COMMON_FALSE_POSITIVES:
                    continue

                # Generate stable substitution token
                token = self._make_token(pattern_name, value)

                # Store mapping
                if token not in mappings:
                    mappings[token] = value
                    entity_counts[pattern_name] = entity_counts.get(pattern_name, 0) + 1

                # Replace in text
                start, end = match.start(), match.end()
                sanitized = sanitized[:start] + token + sanitized[end:]

        if mappings:
            self.vault.store(request_id, mappings)
            logger.info(
                f"Sanitized {sum(entity_counts.values())} entities "
                f"({', '.join(f'{k}:{v}' for k, v in entity_counts.items())}) "
                f"for request {request_id}"
            )

        return SanitizeResult(
            sanitized_text=sanitized,
            entity_counts=entity_counts,
            was_modified=bool(mappings),
            request_id=request_id,
        )

    def restore(self, text: str, request_id: str) -> str:
        """Reverse substitution in the model response using vault mappings.

        Looks up the token→original mapping for this request_id and replaces
        all tokens back to their original values.
        """
        if not text or not request_id:
            return text

        mappings = self.vault.retrieve(request_id)
        if not mappings:
            return text

        restored = text
        for token, original in mappings.items():
            restored = restored.replace(token, original)

        return restored

    def get_stats(self, request_id: str) -> dict:
        """Return entity type counts for a request (never actual values).

        Used for provenance logging — records what types of PII were masked
        without exposing the actual PII.
        """
        mappings = self.vault.retrieve(request_id)
        if not mappings:
            return {}

        type_counts = {}
        for token in mappings:
            # Token format: [TYPE_xxxx]
            match = re.match(r"\[([A-Z_]+)_[a-f0-9]+\]", token)
            if match:
                entity_type = match.group(1).lower()
                type_counts[entity_type] = type_counts.get(entity_type, 0) + 1

        return type_counts

    @staticmethod
    def _make_token(entity_type: str, value: str) -> str:
        """Generate a stable substitution token for a PII value.

        Uses MD5 hash of the value to produce a deterministic 4-char suffix.
        Same value always produces the same token.
        """
        suffix = hashlib.md5(value.encode("utf-8")).hexdigest()[:4]
        return f"[{entity_type.upper()}_{suffix}]"
