# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 GuardEx
"""PolicyOverride -- Sparse, composable policy overrides.

A PolicyOverride represents a partial policy modification. Only non-None
fields are applied during composition. This is the atomic unit of the
context-aware policy system.

Composition follows semilattice rules (monotonic security):
  - Booleans: OR (enable wins -- True is more restrictive)
  - Thresholds: MIN (most sensitive wins)
  - Sets: UNION (more detection is more restrictive)
  - Actions: MAX_SEVERITY (block > mask > none)
  - fail_open: AND (False/strict wins -- the one exception)

When to use PolicyOverride vs GuardExPolicy
-------------------------------------------
Use ``GuardExPolicy`` to define your application's *static baseline* - the
security defaults that apply universally regardless of request context.

Use ``PolicyOverride`` (via ``context_profiles`` or ``CachedPolicyResolver``)
to express *context-sensitive adjustments* that tighten policy for specific
situations without rewriting the whole baseline. Examples:

- Add GDPR PII entities only for EU region users.
- Enforce ``fail_open=False`` only in production.
- Add category S14 block only for tool_call requests.

PolicyOverride fields are *additive and monotonically non-decreasing in
strictness* - overrides can only make policy stricter, never looser.
See ``policy_resolver.resolve_policy()`` for the composition algorithm.
"""

from __future__ import annotations

from dataclasses import dataclass, fields
from typing import Optional, List, Literal


@dataclass
class PolicyOverride:
    """A sparse set of policy fields to override.

    Only non-None fields participate in composition. This keeps
    rules minimal and focused -- a region rule only needs to specify
    the PII entities it adds, not every field.

    Parameters
    ----------
    pii_enabled : bool, optional
        Enable PII detection. OR composition (True wins).
    pii_entities_add : list[str], optional
        PII entity types to ADD. UNION composition (never removes).
    pii_action : str, optional
        PII action: "mask" or "block". MAX_SEVERITY composition.
    pii_threshold : float, optional
        PII detection threshold. MIN composition (lower = more sensitive).
    block_on_unsafe_input : bool, optional
        Block unsafe input. OR composition (True wins).
    block_on_unsafe_output : bool, optional
        Block unsafe output. OR composition (True wins).
    blocked_categories_add : list[str], optional
        Safety categories to ADD. UNION composition (never removes).
    fail_open : bool, optional
        Fail-open behavior. AND composition (False wins).
    timeout : int, optional
        Request timeout. MIN composition (faster = stricter).
    cascade_mode : str, optional
        Cascade mode: "safety" or "speed". MAX_STRICTNESS composition (safety wins).
    audit_logging : bool, optional
        Enable audit logging. OR composition (True wins).
    detailed_logging : bool, optional
        Enable detailed logging. OR composition (True wins).
    """

    # PII overrides
    pii_enabled: Optional[bool] = None
    pii_entities_add: Optional[List[str]] = None
    pii_action: Optional[Literal["mask", "block"]] = None
    pii_threshold: Optional[float] = None

    # Classification overrides
    block_on_unsafe_input: Optional[bool] = None
    block_on_unsafe_output: Optional[bool] = None
    blocked_categories_add: Optional[List[str]] = None

    # Operational overrides
    fail_open: Optional[bool] = None
    timeout: Optional[int] = None

    # Cascade tuning
    cascade_mode: Optional[Literal["safety", "speed"]] = None

    # Logging
    audit_logging: Optional[bool] = None
    detailed_logging: Optional[bool] = None

    def is_empty(self) -> bool:
        """True if no fields are set (all None)."""
        return all(getattr(self, f.name) is None for f in fields(self))
