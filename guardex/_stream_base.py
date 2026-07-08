# SPDX-License-Identifier: Apache-2.0
"""Shared helpers for StreamGuard / AsyncStreamGuard.

Both classes accumulate text chunks, flush at size + content-boundary
thresholds, and (optionally) restore vault tokens.  Anything that doesn't
require ``await`` lives here so the sync and async streamers stay aligned.
"""
from __future__ import annotations

import re
from typing import Literal, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from .pii_vault import PIIVault

# Sentinels used by vault-restore logic to detect partial vault tokens at
# chunk boundaries.  Kept here so both stream guards share the same values.
VAULT_TOKEN_PREFIX = "{{pii:"
VAULT_TOKEN_END    = "}}"

# Literal alias for the public restore_mode kwarg.
VaultRestoreMode = Literal["off", "buffered", "stream-safe"]

# Content-boundary regexes used by _should_flush.
_SENTENCE_BOUNDARY = re.compile(r"[.!?]\s+")
_PARAGRAPH_BREAK   = re.compile(r"\n\s*\n")
_CODE_BLOCK_CLOSE  = re.compile(r"```\s*\n")

# Minimum chars before checking for content boundaries.
MIN_BOUNDARY_CHECK = 50

# Input gates - PII masking applies here only.  Output gates skip PII
# action so LLM-generated text (character names in stories, etc.) is not
# masked as real personal data.
INPUT_GATES = ("input", "prompt", "tool_input", "retrieval_query")


def has_content_boundary(text: str) -> bool:
    """Return True if the buffer contains a natural content boundary."""
    return bool(
        _SENTENCE_BOUNDARY.search(text)
        or _PARAGRAPH_BREAK.search(text)
        or _CODE_BLOCK_CLOSE.search(text)
    )


def should_flush(buffer: str, flush_every: int) -> bool:
    """Apply the size + boundary heuristic shared by both stream guards."""
    if len(buffer) >= flush_every:
        return True
    if len(buffer) > MIN_BOUNDARY_CHECK:
        return has_content_boundary(buffer)
    return False


def split_for_vault_restore(
    text: str,
    pending: str,
    vault: Optional["PIIVault"],
    restore_mode: VaultRestoreMode,
) -> tuple[str, str]:
    """Apply vault restore_mode to ``text`` and return ``(safe_to_emit, new_pending)``.

    Used by both stream guards to decide what's safe to yield now vs what
    needs to wait until a partial ``{{pii:...`` token closes.
    """
    if restore_mode == "off" or vault is None:
        return text, pending
    if restore_mode == "buffered":
        return "", pending + text
    # stream-safe: hold from the last open token without close
    combined = pending + text
    last_open = combined.rfind(VAULT_TOKEN_PREFIX)
    last_close = combined.rfind(VAULT_TOKEN_END)
    if last_open != -1 and last_open > last_close:
        safe, new_pending = combined[:last_open], combined[last_open:]
    else:
        safe, new_pending = combined, ""
    return (vault.restore(safe) if safe else ""), new_pending


def enforce_classify_block(policy, gate: str) -> bool:
    """Whether an unsafe classify verdict is enforced for this gate.

    Mirrors ``_enforce_block``: observe-only mode
    (``block_on_unsafe_input``/``block_on_unsafe_output``) suppresses the
    classify block. Scope, injection, and safety routes always enforce.
    """
    if gate in INPUT_GATES:
        return policy.block_on_unsafe_input
    return policy.block_on_unsafe_output


def classify_should_block(classify: dict, min_confidence: float) -> bool:
    """Whether a classify verdict blocks, honoring the min-confidence override.

    Mirrors ``_parse_screen_result``: an unsafe verdict below
    ``classify_min_confidence`` is treated as safe so streaming and
    ``Guard.screen()`` agree.
    """
    if classify.get("safe", True):
        return False
    if min_confidence > 0.0 and classify.get("confidence", 1.0) < min_confidence:
        return False
    return True


def run_local_gates(text, gate, injection_check, safety_route_check) -> None:
    """Run the client-side injection and safety-route gates on a buffer.

    Mirrors the pre/post-transport gates in ``Guard.screen`` so streaming
    applies the same protections. Raises ``GuardExViolation`` on a block.
    ``injection_check`` returns ``(blocked, note)``; ``safety_route_check``
    returns a ``SafetyRouteOutcome`` (or None). Either may be None to skip.
    """
    from .exceptions import GuardExViolation

    if injection_check is not None and gate in INPUT_GATES:
        blocked, note = injection_check(text)
        if blocked:
            raise GuardExViolation(stage=gate, category="injection", description=note)

    if safety_route_check is not None:
        outcome = safety_route_check(text)
        if outcome is not None and outcome.matched and outcome.action == "block":
            raise GuardExViolation(
                stage=gate, category="safety_route", description=outcome.route_name,
            )


def screen_kwargs_for_buffer(
    policy,
    gate: str,
    audit_log: bool = False,
    mask_output_pii: bool = False,
) -> dict:
    """Build the keyword arguments shared by sync and async ``client.screen``
    calls inside the stream guards.

    On output gates PII masking is off by default so LLM-generated text
    (character names in stories, etc.) is not rewritten as real personal
    data. Set ``mask_output_pii=True`` to mask PII on output gates too.
    """
    mask_pii = policy.pii_enabled and (gate in INPUT_GATES or mask_output_pii)
    kwargs = {
        "pii_action": policy.pii_action if mask_pii else "none",
        "categories": policy.blocked_categories,
        "pii_entities": policy.pii_entities if mask_pii else None,
        "pii_threshold": policy.pii_threshold,
        "cascade_mode": policy.cascade_mode,
        "audit_log": audit_log,
    }
    ts = policy.topic_scope
    if ts and ts.topics:
        kwargs["scope_topics"] = ts.topics
        if ts.utterances:
            kwargs["scope_utterances"] = ts.utterances
        if ts.examples:
            kwargs["scope_examples"] = ts.examples
        kwargs["scope_width"] = ts.scope_width
        if ts.threshold is not None:
            kwargs["scope_threshold"] = ts.threshold
        if ts.alpha > 0.0:
            kwargs["scope_alpha"] = ts.alpha
    return kwargs
