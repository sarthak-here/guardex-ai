# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 GuardEx
"""PolicyResolver -- Context to effective policy resolution.

The resolver is a pure function: (base_policy, context, rules) -> effective_policy.
It composes policy overrides using semilattice join operations that are provably
safe (monotonically non-decreasing in strictness).

Composition rules:
  - Booleans: OR (True/enabled wins)
  - Thresholds: MIN (most sensitive wins)
  - Sets: UNION (additive only, never removes)
  - Actions: MAX_SEVERITY (block > mask > none)
  - fail_open: AND (False/strict wins)

These operations are commutative and associative, so application order
does not affect the result for security-critical fields.

Usage::

    from guardex.policy_resolver import resolve_policy, CachedPolicyResolver
    from guardex.policy import GuardExPolicy
    from guardex.context import GuardExContext, DeploymentContext

    base = GuardExPolicy()
    ctx = GuardExContext(deployment=DeploymentContext.PRODUCTION)
    effective = resolve_policy(base, ctx)
"""

from __future__ import annotations

import logging
from dataclasses import replace
from threading import RLock
from typing import List, Optional

from .context import GuardExContext
from .policy import GuardExPolicy
from .policy_override import PolicyOverride
from .context_profiles import (
    DEPLOYMENT_PROFILES, REGION_PROFILES, INDUSTRY_PROFILES,
    AUTH_PROFILES, REQUEST_TYPE_PROFILES,
)

logger = logging.getLogger(__name__)

# Action severity ordering for MAX_SEVERITY composition
_ACTION_SEVERITY: dict[str, int] = {"none": 0, "mask": 1, "block": 2}


def resolve_policy(
    base: GuardExPolicy,
    context: GuardExContext,
    custom_rules: Optional[List[PolicyOverride]] = None,
) -> GuardExPolicy:
    """Resolve an effective policy from base policy + context.

    This is a PURE FUNCTION: same inputs always produce the same output.
    Deterministic and side-effect free, safe to cache.

    Resolution order (lowest to highest precedence):

        base policy
          -> deployment profile
          -> region profile
          -> industry profile
          -> auth status profile
          -> request type profile
          -> custom rules (in order)

    Parameters
    ----------
    base : GuardExPolicy
        The project's base policy (from dashboard config or code).
    context : GuardExContext
        The complete context for this request.
    custom_rules : list[PolicyOverride], optional
        Additional project-specific context rules to apply after
        built-in profiles.

    Returns
    -------
    GuardExPolicy
        The effective policy with all context overrides composed.
    """
    overrides: List[PolicyOverride] = []

    # Layer 1: Deployment
    dep = DEPLOYMENT_PROFILES.get(context.deployment)
    if dep and not dep.is_empty():
        overrides.append(dep)

    # Layer 2: Region
    region = REGION_PROFILES.get(context.user.region)
    if region and not region.is_empty():
        overrides.append(region)

    # Layer 3: Industry
    industry = INDUSTRY_PROFILES.get(context.user.industry)
    if industry and not industry.is_empty():
        overrides.append(industry)

    # Layer 4: Auth status
    auth = AUTH_PROFILES.get(context.user.auth_status)
    if auth and not auth.is_empty():
        overrides.append(auth)

    # Layer 5: Request type
    req = REQUEST_TYPE_PROFILES.get(context.request.request_type)
    if req and not req.is_empty():
        overrides.append(req)

    # Layer 6: Custom project rules
    if custom_rules:
        overrides.extend(r for r in custom_rules if not r.is_empty())

    if not overrides:
        return base

    return _apply_overrides(base, overrides)


def _apply_overrides(
    base: GuardExPolicy,
    overrides: List[PolicyOverride],
) -> GuardExPolicy:
    """Apply a sequence of overrides to a base policy.

    Uses semilattice join operations:
      - bool fields: OR (True wins)
      - float thresholds: MIN (most sensitive wins)
      - list fields: UNION (additive only)
      - action fields: MAX_SEVERITY (block > mask > none)

    Special case: fail_open uses AND (False wins). This is because
    fail_open=True is a leniency, and our composition must be
    monotonically non-decreasing in strictness.
    """
    pii_enabled = base.pii_enabled
    pii_entities = set(base.pii_entities)
    pii_action = base.pii_action
    pii_threshold = base.pii_threshold

    block_input = base.block_on_unsafe_input
    block_output = base.block_on_unsafe_output
    blocked_cats = set(base.blocked_categories)

    fail_open = base.fail_open
    timeout = base.timeout

    # Operational mode fields - carry through composition
    cascade_mode = base.cascade_mode
    audit_logging = base.audit_logging
    detailed_logging = base.detailed_logging

    for ov in overrides:
        # Booleans: OR (True/enabled wins)
        if ov.pii_enabled is True:
            pii_enabled = True
        if ov.block_on_unsafe_input is True:
            block_input = True
        if ov.block_on_unsafe_output is True:
            block_output = True

        # fail_open: AND (False/strict wins)
        if ov.fail_open is False:
            fail_open = False

        # audit_logging / detailed_logging: OR (True wins)
        if ov.audit_logging is True:
            audit_logging = True
        if ov.detailed_logging is True:
            detailed_logging = True

        # Thresholds: MIN (most sensitive wins)
        if ov.pii_threshold is not None:
            pii_threshold = min(pii_threshold, ov.pii_threshold)

        # Sets: UNION (additive only)
        if ov.pii_entities_add:
            pii_entities |= set(ov.pii_entities_add)
        if ov.blocked_categories_add:
            blocked_cats |= set(ov.blocked_categories_add)

        # Actions: MAX_SEVERITY (block > mask > none)
        if ov.pii_action is not None:
            if _ACTION_SEVERITY.get(ov.pii_action, 0) > _ACTION_SEVERITY.get(pii_action, 0):
                pii_action = ov.pii_action

        # Timeout: MIN (shorter = more aggressive)
        if ov.timeout is not None:
            timeout = min(timeout, ov.timeout)

        # cascade_mode: MAX_STRICTNESS (safety > speed)
        # "safety" cannot be downgraded to "speed" - monotonically non-decreasing
        # in strictness, matching the semilattice principle for all other fields.
        if ov.cascade_mode == "safety":
            cascade_mode = "safety"
        elif ov.cascade_mode == "speed" and cascade_mode != "safety":
            cascade_mode = "speed"

    # Use dataclasses.replace so every field on `base` that we did NOT
    # override (safety_routes, pii_deny_list, pii_allow_list,
    # pii_custom_regex, pii_custom_context_keywords, refusal_messages,
    # any future field) is preserved automatically.
    return replace(
        base,
        block_on_unsafe_input=block_input,
        block_on_unsafe_output=block_output,
        blocked_categories=sorted(blocked_cats),
        fail_open=fail_open,
        timeout=timeout,
        pii_enabled=pii_enabled,
        pii_entities=sorted(pii_entities),
        pii_action=pii_action,
        pii_threshold=pii_threshold,
        cascade_mode=cascade_mode,
        audit_logging=audit_logging,
        detailed_logging=detailed_logging,
    )


class CachedPolicyResolver:
    """Bounded FIFO-cached policy resolver for production use.

    Caches resolved policies by context hash to avoid repeated
    computation.  Cache is size-bounded; eviction order is insertion
    (FIFO) rather than access (LRU) for simplicity - adequate when
    contexts stabilise after warm-up.  Thread-safe via internal RLock.

    Parameters
    ----------
    base_policy : GuardExPolicy
        The project's base policy.
    custom_rules : list[PolicyOverride], optional
        Project-specific context rules applied after built-in profiles.
    max_cache_size : int
        Maximum cached resolved policies (default 256).

    Usage::

        resolver = CachedPolicyResolver(base_policy, custom_rules=rules)
        effective = resolver.resolve(context)
        print(resolver.stats)
    """

    def __init__(
        self,
        base_policy: GuardExPolicy,
        custom_rules: Optional[List[PolicyOverride]] = None,
        max_cache_size: int = 256,
    ):
        self._base = base_policy
        self._custom_rules = custom_rules or []
        self._max_cache_size = max_cache_size
        self._cache: dict[str, GuardExPolicy] = {}
        self._cache_hits = 0
        self._cache_misses = 0
        # RLock so multi-worker setups (gunicorn, uvicorn) don't race on
        # the dict + counters.  Reentrant in case resolve() ever calls
        # back into the resolver from a callback.
        self._lock = RLock()

    def resolve(self, context: GuardExContext) -> GuardExPolicy:
        """Resolve effective policy for context, with caching.

        Returns cached result if available. Cache key is the context's
        deterministic hash.  Thread-safe via an internal RLock.
        """
        key = context.cache_key()

        with self._lock:
            cached = self._cache.get(key)
            if cached is not None:
                self._cache_hits += 1
                return cached
            self._cache_misses += 1

        # Compute outside the lock - resolve_policy is pure and slow-ish.
        policy = resolve_policy(self._base, context, self._custom_rules)

        with self._lock:
            # Re-check: another thread may have populated this key while
            # we were computing.  First writer wins (deterministic since
            # resolve_policy is pure).
            existing = self._cache.get(key)
            if existing is not None:
                return existing
            if len(self._cache) >= self._max_cache_size:
                # Insertion-order eviction (FIFO).  True LRU would track
                # access order; FIFO is good enough for bounded warm-up.
                oldest_key = next(iter(self._cache))
                del self._cache[oldest_key]
            self._cache[key] = policy
            return policy

    def invalidate(self) -> None:
        """Clear the resolved-policy cache.

        Call this whenever ``base_policy`` or ``custom_rules`` change.
        Note: hit/miss counters are also reset so ``stats`` reflects
        performance since the last policy change, not lifetime totals.
        """
        with self._lock:
            self._cache.clear()
            self._cache_hits = 0
            self._cache_misses = 0

    @property
    def stats(self) -> dict:
        """Cache performance statistics."""
        with self._lock:
            total = self._cache_hits + self._cache_misses
            return {
                "cache_size": len(self._cache),
                "max_cache_size": self._max_cache_size,
                "hits": self._cache_hits,
                "misses": self._cache_misses,
                "hit_rate": round(self._cache_hits / max(total, 1) * 100, 1),
            }
