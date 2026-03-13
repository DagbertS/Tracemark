"""Policy Engine — orchestrates policy evaluation across the interception pipeline."""

from __future__ import annotations

import logging
import re
import uuid
from collections import Counter
from datetime import datetime, timezone
from typing import Any

from .base import BasePolicy, PolicyVerdict, PolicyResult, PolicyAction, PolicyType
from .pii_policy import PIIDetectionPolicy
from .blocklist_policy import TopicBlocklistPolicy
from .confidence_policy import ConfidenceThresholdPolicy

logger = logging.getLogger("tracemark.policy_engine")

# Map policy type identifiers to their implementation classes.
# New custom policies created via the API use 'custom-blocklist' or 'custom-regex'.
POLICY_CLASS_MAP = {
    "pii-detection": PIIDetectionPolicy,
    "topic-blocklist": TopicBlocklistPolicy,
    "confidence-check": ConfidenceThresholdPolicy,
}


class PolicyEngine:
    """Evaluates all active policies against intercepted content."""

    def __init__(self, policy_configs: list[dict[str, Any]]):
        self.policies: list[BasePolicy] = []
        self._pending_policies: list[dict[str, Any]] = []  # Policies awaiting human approval
        for pc in policy_configs:
            self._load_policy(pc)
        logger.info(f"PolicyEngine initialized with {len(self.policies)} policies")

    def _load_policy(self, pc: dict[str, Any]) -> BasePolicy | None:
        """Load a single policy from config dict."""
        policy_id = pc["id"]
        # Determine the correct class — check by explicit policy_class first, then id
        policy_class_name = pc.get("policy_class", policy_id)
        cls = POLICY_CLASS_MAP.get(policy_class_name)
        if cls is None:
            # For custom policies, infer the best class from the config
            if pc.get("config", {}).get("patterns"):
                cls = PIIDetectionPolicy
            elif pc.get("config", {}).get("forbidden_topics"):
                cls = TopicBlocklistPolicy
            elif pc.get("config", {}).get("uncertainty_phrases"):
                cls = ConfidenceThresholdPolicy
            else:
                # Default to blocklist for custom policies with no specific config structure
                cls = TopicBlocklistPolicy

        try:
            policy = cls(
                policy_id=policy_id,
                name=pc["name"],
                policy_type=PolicyType(pc["type"]),
                action=PolicyAction(pc["action"]),
                config=pc.get("config", {}),
                enabled=pc.get("enabled", True),
            )
            self.policies.append(policy)
            return policy
        except Exception as e:
            logger.error(f"Failed to load policy {policy_id}: {e}")
            return None

    def add_policy(self, policy_config: dict[str, Any]) -> dict[str, Any]:
        """Dynamically add a new policy at runtime."""
        policy_id = policy_config.get("id") or f"custom-{uuid.uuid4().hex[:8]}"
        policy_config["id"] = policy_id

        # Check for duplicate ID
        if any(p.policy_id == policy_id for p in self.policies):
            return {"error": f"Policy with id '{policy_id}' already exists", "status": "rejected"}

        policy = self._load_policy(policy_config)
        if policy:
            logger.info(f"Policy dynamically added: {policy_id}")
            return {"status": "active", "policy": self._policy_to_dict(policy)}
        return {"error": "Failed to create policy from config", "status": "rejected"}

    def update_policy(self, policy_id: str, updates: dict[str, Any]) -> dict[str, Any]:
        """Update an existing policy's configuration at runtime."""
        for i, p in enumerate(self.policies):
            if p.policy_id == policy_id:
                if "enabled" in updates:
                    p.enabled = updates["enabled"]
                if "action" in updates:
                    p.action = PolicyAction(updates["action"])
                if "name" in updates:
                    p.name = updates["name"]
                if "config" in updates:
                    p.config = updates["config"]
                    # Re-initialize policy with new config
                    new_config = {
                        "id": p.policy_id,
                        "name": p.name,
                        "type": p.policy_type.value,
                        "action": p.action.value,
                        "config": p.config,
                        "enabled": p.enabled,
                    }
                    cls = type(p)
                    try:
                        new_policy = cls(
                            policy_id=p.policy_id,
                            name=p.name,
                            policy_type=p.policy_type,
                            action=p.action,
                            config=p.config,
                            enabled=p.enabled,
                        )
                        self.policies[i] = new_policy
                    except Exception as e:
                        logger.error(f"Policy re-init failed: {e}")
                        return {"error": str(e), "status": "failed"}
                return {"status": "updated", "policy": self._policy_to_dict(self.policies[i])}
        return {"error": f"Policy '{policy_id}' not found", "status": "not_found"}

    def delete_policy(self, policy_id: str) -> dict[str, Any]:
        """Remove a policy by ID."""
        for i, p in enumerate(self.policies):
            if p.policy_id == policy_id:
                removed = self.policies.pop(i)
                logger.info(f"Policy removed: {policy_id}")
                return {"status": "deleted", "policy_id": policy_id, "name": removed.name}
        return {"error": f"Policy '{policy_id}' not found", "status": "not_found"}

    def suggest_policies_from_history(self, provenance_entries: list[dict]) -> list[dict[str, Any]]:
        """Analyze historical interceptions and suggest new policy rules.

        Examines patterns in violations, blocked content, and warnings to
        recommend new policies. Suggested policies are marked as 'pending_approval'
        and must be routed to a human for review before activation.
        """
        suggestions: list[dict[str, Any]] = []

        # Collect all violation details from history
        violation_patterns: list[str] = []
        warning_patterns: list[str] = []
        blocked_content_snippets: list[str] = []
        models_seen: Counter = Counter()
        callers_seen: Counter = Counter()

        for entry in provenance_entries:
            models_seen[entry.get("upstream_model", "unknown")] += 1
            callers_seen[entry.get("caller_id", "unknown")] += 1

            verdicts = entry.get("policy_verdicts", [])
            for v in verdicts:
                if v.get("result") == "VIOLATION":
                    matched = v.get("matched_rule", "")
                    if matched:
                        violation_patterns.append(matched)
                    details = v.get("details", {})
                    # Extract matched content from PII violations
                    if "matched_patterns" in details:
                        for pat_name, matches in details["matched_patterns"].items():
                            blocked_content_snippets.extend(matches if isinstance(matches, list) else [])
                elif v.get("result") == "WARNING":
                    matched = v.get("matched_rule", "")
                    if matched:
                        warning_patterns.append(matched)

            # Analyze response bodies for recurring patterns
            response_body = entry.get("response_body", "")
            if response_body and entry.get("overall_verdict") in ("VIOLATION", "BLOCKED", "REMEDIATED"):
                blocked_content_snippets.append(response_body[:200])

        # Suggestion 1: If we see repeated violations from a specific caller, suggest a caller-specific policy
        for caller, count in callers_seen.items():
            if caller == "unknown":
                continue
            caller_violations = sum(
                1 for e in provenance_entries
                if e.get("caller_id") == caller
                and e.get("overall_verdict") in ("VIOLATION", "BLOCKED", "REMEDIATED")
            )
            if caller_violations >= 3:
                suggestions.append({
                    "id": f"auto-restrict-{caller.replace(' ', '-').lower()[:20]}",
                    "name": f"Restrict high-risk caller: {caller}",
                    "type": "BOTH",
                    "action": "BLOCK",
                    "policy_class": "topic-blocklist",
                    "config": {
                        "forbidden_topics": ["unrestricted access"],
                        "description": f"Auto-suggested: Caller '{caller}' has {caller_violations} violations in recent history",
                    },
                    "reason": f"Caller '{caller}' triggered {caller_violations} violations out of {count} total calls",
                    "confidence": min(0.95, 0.5 + (caller_violations / count) * 0.5),
                    "status": "pending_approval",
                    "suggested_at": datetime.now(timezone.utc).isoformat(),
                })

        # Suggestion 2: Detect new PII-like patterns not covered by existing rules
        # Look for patterns in blocked content that match common sensitive data formats
        new_patterns_found = set()
        ssn_pattern = re.compile(r'\b\d{3}-\d{2}-\d{4}\b')
        iban_pattern = re.compile(r'\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}([A-Z0-9]?){0,16}\b')
        ip_pattern = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')

        for snippet in blocked_content_snippets:
            if ssn_pattern.search(snippet):
                new_patterns_found.add("ssn")
            if iban_pattern.search(snippet):
                new_patterns_found.add("iban")
            if ip_pattern.search(snippet):
                new_patterns_found.add("ip_address")

        # Check which patterns are already covered
        existing_pattern_names = set()
        for p in self.policies:
            if hasattr(p, 'config') and 'patterns' in p.config:
                for pat in p.config['patterns']:
                    existing_pattern_names.add(pat.get('name', ''))

        new_pii_patterns = []
        pattern_regexes = {
            "ssn": {"name": "ssn", "regex": r"\b\d{3}-\d{2}-\d{4}\b"},
            "iban": {"name": "iban", "regex": r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}([A-Z0-9]?){0,16}\b"},
            "ip_address": {"name": "ip_address", "regex": r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"},
        }
        for pat_name in new_patterns_found:
            if pat_name not in existing_pattern_names:
                new_pii_patterns.append(pattern_regexes[pat_name])

        if new_pii_patterns:
            suggestions.append({
                "id": f"auto-pii-extended-{uuid.uuid4().hex[:6]}",
                "name": "Extended PII Detection (auto-suggested)",
                "type": "BOTH",
                "action": "BLOCK",
                "policy_class": "pii-detection",
                "config": {"patterns": new_pii_patterns},
                "reason": f"Detected {len(new_pii_patterns)} new PII pattern(s) in historical violations: {', '.join(p['name'] for p in new_pii_patterns)}",
                "confidence": 0.85,
                "status": "pending_approval",
                "suggested_at": datetime.now(timezone.utc).isoformat(),
            })

        # Suggestion 3: If many warnings from confidence check, suggest stricter enforcement
        if len(warning_patterns) >= 5:
            suggestions.append({
                "id": f"auto-confidence-strict-{uuid.uuid4().hex[:6]}",
                "name": "Strict Confidence Enforcement (auto-suggested)",
                "type": "POST_CALL",
                "action": "BLOCK",
                "policy_class": "confidence-check",
                "config": {
                    "uncertainty_phrases": [
                        "I am not sure", "I cannot guarantee", "you should consult",
                        "I may be wrong", "this is not financial advice",
                        "I don't have enough information", "this could be incorrect",
                    ],
                },
                "reason": f"Detected {len(warning_patterns)} uncertainty warnings — suggest upgrading to BLOCK action",
                "confidence": 0.7,
                "status": "pending_approval",
                "suggested_at": datetime.now(timezone.utc).isoformat(),
            })

        # Suggestion 4: Extract recurring blocked topics and suggest expanding the blocklist
        violation_topic_counts = Counter(violation_patterns)
        frequent_violations = [topic for topic, count in violation_topic_counts.items() if count >= 2]
        if frequent_violations:
            # Check for topics not already in blocklist
            existing_topics = set()
            for p in self.policies:
                if hasattr(p, 'config') and 'forbidden_topics' in p.config:
                    existing_topics.update(t.lower() for t in p.config['forbidden_topics'])

            new_topics = [t for t in frequent_violations if t.lower() not in existing_topics]
            if new_topics:
                suggestions.append({
                    "id": f"auto-blocklist-expand-{uuid.uuid4().hex[:6]}",
                    "name": "Expanded Topic Blocklist (auto-suggested)",
                    "type": "BOTH",
                    "action": "BLOCK",
                    "policy_class": "topic-blocklist",
                    "config": {"forbidden_topics": new_topics},
                    "reason": f"These topics triggered repeated violations: {', '.join(new_topics)}",
                    "confidence": 0.8,
                    "status": "pending_approval",
                    "suggested_at": datetime.now(timezone.utc).isoformat(),
                })

        # Store suggestions for later approval
        self._pending_policies.extend(suggestions)
        return suggestions

    def get_pending_policies(self) -> list[dict[str, Any]]:
        """Return policies awaiting human approval."""
        return list(self._pending_policies)

    def approve_pending_policy(self, policy_id: str) -> dict[str, Any]:
        """Approve a pending policy and activate it."""
        for i, pending in enumerate(self._pending_policies):
            if pending["id"] == policy_id:
                policy_config = dict(pending)
                policy_config["enabled"] = True
                policy_config.pop("reason", None)
                policy_config.pop("confidence", None)
                policy_config.pop("status", None)
                policy_config.pop("suggested_at", None)
                result = self.add_policy(policy_config)
                if result.get("status") == "active":
                    self._pending_policies.pop(i)
                    return {"status": "approved_and_active", "policy": result.get("policy")}
                return result
        return {"error": f"Pending policy '{policy_id}' not found", "status": "not_found"}

    def reject_pending_policy(self, policy_id: str) -> dict[str, Any]:
        """Reject and remove a pending policy suggestion."""
        for i, pending in enumerate(self._pending_policies):
            if pending["id"] == policy_id:
                self._pending_policies.pop(i)
                return {"status": "rejected", "policy_id": policy_id}
        return {"error": f"Pending policy '{policy_id}' not found", "status": "not_found"}

    def evaluate_pre_call(self, content: str) -> list[PolicyVerdict]:
        return self._evaluate(content, "PRE_CALL")

    def evaluate_post_call(self, content: str) -> list[PolicyVerdict]:
        return self._evaluate(content, "POST_CALL")

    def _evaluate(self, content: str, phase: str) -> list[PolicyVerdict]:
        verdicts = []
        for policy in self.policies:
            if not policy.applies_to_phase(phase):
                continue
            try:
                verdict = policy.evaluate(content)
                verdicts.append(verdict)
            except Exception as e:
                # Fail-open: log error, record INDETERMINATE, continue
                logger.error(f"Policy {policy.policy_id} raised exception: {e}")
                verdicts.append(PolicyVerdict(
                    policy_id=policy.policy_id,
                    policy_name=policy.name,
                    result=PolicyResult.PASS,
                    details={"error": str(e), "fail_open": True},
                ))
        return verdicts

    def has_blocking_violation(self, verdicts: list[PolicyVerdict]) -> bool:
        return any(
            v.result == PolicyResult.VIOLATION and v.action_taken == PolicyAction.BLOCK
            for v in verdicts
        )

    def get_overall_verdict(self, verdicts: list[PolicyVerdict]) -> str:
        if any(v.result == PolicyResult.VIOLATION and v.action_taken == PolicyAction.BLOCK for v in verdicts):
            return "BLOCKED"
        if any(v.result == PolicyResult.VIOLATION for v in verdicts):
            return "VIOLATION"
        if any(v.result == PolicyResult.WARNING for v in verdicts):
            return "WARNING"
        return "PASS"

    def set_policy_remediation_text(self, policy_id: str, text: str) -> bool:
        for p in self.policies:
            if p.policy_id == policy_id:
                p.remediation_text = text
                return True
        return False

    def _policy_to_dict(self, p: BasePolicy) -> dict:
        return {
            "id": p.policy_id,
            "name": p.name,
            "type": p.policy_type.value,
            "action": p.action.value,
            "enabled": p.enabled,
            "config": p.config,
            "remediation_text": p.remediation_text,
        }

    def get_active_policies(self) -> list[dict]:
        return [self._policy_to_dict(p) for p in self.policies]
