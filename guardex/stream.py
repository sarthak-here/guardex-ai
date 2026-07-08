# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 GuardEx
"""Buffer-and-screen for streaming LLM responses.

Chunks are accumulated until the buffer crosses ``flush_every`` chars or
hits a content boundary (sentence end, paragraph break, closing fenced
code block). On flush the buffer is screened: unsafe → raise, safe →
yield. The remainder is flushed when the stream ends.

Usage::

    guard = Guard()
    for chunk in guard.stream(openai_chunks(), gate="output"):
        print(chunk, end="", flush=True)

    async for chunk in guard.astream(anthropic_chunks(), gate="output"):
        print(chunk, end="", flush=True)
"""

from __future__ import annotations

import logging
from typing import Any, AsyncIterator, Callable, Iterator, Optional, Tuple, TYPE_CHECKING

from ._stream_base import (
    INPUT_GATES,
    MIN_BOUNDARY_CHECK as _MIN_BOUNDARY_CHECK,
    VAULT_TOKEN_END as _VAULT_TOKEN_END,
    VAULT_TOKEN_PREFIX as _VAULT_TOKEN_PREFIX,
    VaultRestoreMode,
    _CODE_BLOCK_CLOSE,
    _PARAGRAPH_BREAK,
    _SENTENCE_BOUNDARY,
    classify_should_block,
    enforce_classify_block,
    has_content_boundary as _has_content_boundary,
    run_local_gates,
    screen_kwargs_for_buffer,
    should_flush as _should_flush_fn,
    split_for_vault_restore,
)
from ._types import gate_to_stage

if TYPE_CHECKING:
    from .pii_vault import PIIVault

logger = logging.getLogger(__name__)

InjectionCheck = Callable[[str], Tuple[bool, Optional[str]]]
SafetyRouteCheck = Callable[[str], Any]


class StreamGuard:
    """Synchronous streaming screener.

    Buffers text chunks and screens them in batches for safety
    and PII detection.  Raises GuardExViolation on unsafe content.

    Pass ``vault=`` to restore vault tokens emitted by the upstream LLM:
    ``"buffered"`` (correctness-first - accumulate the whole stream then
    yield) or ``"stream-safe"`` (preserves streaming UX - yields the
    longest prefix that does not contain an open ``{{pii:`` token).
    """

    def __init__(
        self,
        client,  # GuardExClient
        policy,  # GuardExPolicy
        gate: str = "output",
        flush_every: int = 256,
        vault: Optional["PIIVault"] = None,
        restore_mode: VaultRestoreMode = "off",
        mask_output_pii: bool = False,
        injection_check: Optional[InjectionCheck] = None,
        safety_route_check: Optional[SafetyRouteCheck] = None,
    ) -> None:
        self._client = client
        self._policy = policy
        self._gate = gate
        self._flush_every = flush_every
        self._vault = vault
        self._restore_mode = restore_mode if vault is not None else "off"
        self._mask_output_pii = mask_output_pii
        self._injection_check = injection_check
        self._safety_route_check = safety_route_check
        self._buffer = ""
        self._total_screened = 0
        # Holds chars that may be inside a partial vault token between flushes.
        self._restore_pending = ""

    def run(self, chunks: Iterator[str]) -> Iterator[str]:
        """Process a stream of text chunks. Yields screened text."""
        for chunk in chunks:
            self._buffer += chunk

            if self._should_flush():
                yield from self._flush()

        # Final flush - don't lose trailing content
        if self._buffer:
            yield from self._flush()

        # Drain any vault-pending tail (stream-safe mode).
        if self._restore_pending:
            yield self._vault.restore(self._restore_pending) if self._vault else self._restore_pending
            self._restore_pending = ""

        logger.debug(
            "StreamGuard complete: screened %d chars total", self._total_screened
        )

    def _restore_emit(self, text: str) -> Iterator[str]:
        """Apply vault restoration according to restore_mode and yield text."""
        emit, self._restore_pending = split_for_vault_restore(
            text, self._restore_pending, self._vault, self._restore_mode,
        )
        if emit or self._restore_mode == "off":
            yield emit
        # buffered/stream-safe with no emit-ready content just updates pending.

    def _should_flush(self) -> bool:
        return _should_flush_fn(self._buffer, self._flush_every)

    def _flush(self) -> Iterator[str]:
        """Screen the buffer contents and yield results."""
        from .exceptions import GuardExViolation

        text = self._buffer
        self._buffer = ""
        self._total_screened += len(text)

        run_local_gates(
            text, self._gate, self._injection_check, self._safety_route_check,
        )

        result, _ = self._client.screen(
            text=text,
            stage=gate_to_stage(self._gate),
            **screen_kwargs_for_buffer(
                self._policy, self._gate,
                audit_log=self._policy.audit_logging,
                mask_output_pii=self._mask_output_pii,
            ),
        )

        # Fail-open: pass through on server error.  Apply vault restore
        # so vault tokens don't leak even when the server is unavailable.
        if result.get("_fail_open"):
            yield from self._restore_emit(text)
            return

        # Check safety. The classify verdict is gated by observe-only mode
        # (block_on_unsafe_input/output), matching _enforce_block; scope,
        # injection, and safety routes always enforce.
        classify = result.get("classify", {})
        if enforce_classify_block(self._policy, self._gate) and classify_should_block(
            classify, self._policy.classify_min_confidence
        ):
            category = classify.get("category")
            logger.warning(
                "StreamGuard blocked at gate=%s: category=%s after %d chars",
                self._gate, category, self._total_screened,
            )
            raise GuardExViolation(
                stage=self._gate,
                category=category,
                description=classify.get("description"),
            )

        # Topic scope is reported in a separate `scope` object, not in
        # `classify.safe`; enforce it here to match Guard.screen().
        scope = result.get("scope")
        if scope is not None and not scope.get("allowed", True):
            logger.warning(
                "StreamGuard blocked at gate=%s: out of topic scope after %d chars",
                self._gate, self._total_screened,
            )
            raise GuardExViolation(
                stage=self._gate,
                category="scope",
                description=scope.get("reason"),
            )

        # Yield masked text if PII was found, otherwise original.
        # Vault restoration (if any) is layered on by _restore_emit.
        yield from self._restore_emit(result.get("text", text))


class AsyncStreamGuard:
    """Asynchronous streaming screener. Same logic, async transport.

    See :class:`StreamGuard` for ``vault=``/``restore_mode=`` semantics.
    """

    def __init__(
        self,
        async_client,  # AsyncGuardExClient
        policy,        # GuardExPolicy
        gate: str = "output",
        flush_every: int = 256,
        vault: Optional["PIIVault"] = None,
        restore_mode: VaultRestoreMode = "off",
        mask_output_pii: bool = False,
        injection_check: Optional[InjectionCheck] = None,
        safety_route_check: Optional[SafetyRouteCheck] = None,
    ) -> None:
        self._client = async_client
        self._policy = policy
        self._gate = gate
        self._flush_every = flush_every
        self._vault = vault
        self._restore_mode = restore_mode if vault is not None else "off"
        self._mask_output_pii = mask_output_pii
        self._injection_check = injection_check
        self._safety_route_check = safety_route_check
        self._buffer = ""
        self._total_screened = 0
        self._restore_pending = ""

    async def run(self, chunks: AsyncIterator[str]) -> AsyncIterator[str]:
        """Process an async stream of text chunks. Yields screened text."""
        async for chunk in chunks:
            self._buffer += chunk

            if self._should_flush():
                async for text in self._aflush():
                    yield text

        # Final flush
        if self._buffer:
            async for text in self._aflush():
                yield text

        # Drain any vault-pending tail.
        if self._restore_pending:
            yield self._vault.restore(self._restore_pending) if self._vault else self._restore_pending
            self._restore_pending = ""

        logger.debug(
            "AsyncStreamGuard complete: screened %d chars total",
            self._total_screened,
        )

    def _restore_emit_chunks(self, text: str) -> list[str]:
        """Apply vault restoration in the async path; return zero-or-one chunks."""
        emit, self._restore_pending = split_for_vault_restore(
            text, self._restore_pending, self._vault, self._restore_mode,
        )
        if self._restore_mode == "off":
            return [emit]
        return [emit] if emit else []

    def _should_flush(self) -> bool:
        return _should_flush_fn(self._buffer, self._flush_every)

    async def _aflush(self) -> AsyncIterator[str]:
        from .exceptions import GuardExViolation

        text = self._buffer
        self._buffer = ""
        self._total_screened += len(text)

        run_local_gates(
            text, self._gate, self._injection_check, self._safety_route_check,
        )

        result, _ = await self._client.screen(
            text=text,
            stage=gate_to_stage(self._gate),
            **screen_kwargs_for_buffer(
                self._policy, self._gate,
                audit_log=self._policy.audit_logging,
                mask_output_pii=self._mask_output_pii,
            ),
        )

        if result.get("_fail_open"):
            for piece in self._restore_emit_chunks(text):
                yield piece
            return

        classify = result.get("classify", {})
        if enforce_classify_block(self._policy, self._gate) and classify_should_block(
            classify, self._policy.classify_min_confidence
        ):
            category = classify.get("category")
            logger.warning(
                "AsyncStreamGuard blocked at gate=%s: category=%s after %d chars",
                self._gate, category, self._total_screened,
            )
            raise GuardExViolation(
                stage=self._gate,
                category=category,
                description=classify.get("description"),
            )

        # Topic scope is reported in a separate `scope` object, not in
        # `classify.safe`; enforce it here to match Guard.screen().
        scope = result.get("scope")
        if scope is not None and not scope.get("allowed", True):
            logger.warning(
                "AsyncStreamGuard blocked at gate=%s: out of topic scope after %d chars",
                self._gate, self._total_screened,
            )
            raise GuardExViolation(
                stage=self._gate,
                category="scope",
                description=scope.get("reason"),
            )

        # Yield masked text if PII was found, otherwise original.
        # Vault restoration (if any) is layered on by _restore_emit_chunks.
        for piece in self._restore_emit_chunks(result.get("text", text)):
            yield piece
