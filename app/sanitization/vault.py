"""In-memory TTL vault for PII substitution mappings.

Each request gets a short-lived vault entry (default 5 minutes) that stores
the mapping from substitution tokens back to original values. This enables
transparent restore after the model responds.

Thread-safe via GIL for the async single-threaded event loop.
"""

from __future__ import annotations

import logging
import time
from typing import Optional

logger = logging.getLogger("tracemark.sanitization.vault")


class VaultStore:
    """In-memory TTL store for PII mappings keyed by request_id."""

    def __init__(self, default_ttl: int = 300):
        self._store: dict = {}  # {request_id: {"mappings": dict, "reverse": dict, "expires": float}}
        self._default_ttl = default_ttl
        self._cleanup_counter = 0

    def store(self, request_id: str, mappings: dict, ttl: Optional[int] = None) -> None:
        """Store token→original mappings for a request.

        Args:
            request_id: Unique request identifier
            mappings: Dict of {substitution_token: original_value}
            ttl: Time-to-live in seconds (default: 300)
        """
        ttl = ttl or self._default_ttl
        # Build reverse mapping (original → token) for efficient sanitization
        reverse = {v: k for k, v in mappings.items()}
        self._store[request_id] = {
            "mappings": mappings,
            "reverse": reverse,
            "expires": time.time() + ttl,
        }
        logger.debug(f"Vault stored {len(mappings)} mappings for request {request_id}")

        # Periodic cleanup every 100 stores
        self._cleanup_counter += 1
        if self._cleanup_counter >= 100:
            self.cleanup()
            self._cleanup_counter = 0

    def retrieve(self, request_id: str) -> Optional[dict]:
        """Retrieve token→original mappings for a request.

        Returns None if the entry has expired or doesn't exist.
        """
        entry = self._store.get(request_id)
        if entry is None:
            return None
        if time.time() > entry["expires"]:
            del self._store[request_id]
            logger.debug(f"Vault entry expired for request {request_id}")
            return None
        return entry["mappings"]

    def cleanup(self) -> int:
        """Remove all expired entries. Returns count of removed entries."""
        now = time.time()
        expired = [k for k, v in self._store.items() if now > v["expires"]]
        for k in expired:
            del self._store[k]
        if expired:
            logger.debug(f"Vault cleanup: removed {len(expired)} expired entries")
        return len(expired)

    @property
    def size(self) -> int:
        """Current number of stored entries (including possibly expired)."""
        return len(self._store)
