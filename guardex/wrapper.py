# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 GuardEx
"""GuardedLLM - wraps any LangChain ``BaseChatModel`` with GuardEx screening.

Pipeline: screen(input) → underlying LLM call → screen(output).

LangChain is optional. Importing this module without ``langchain-core``
raises ``ImportError``.

Usage::

    from guardex import GuardedLLM
    from langchain_openai import ChatOpenAI

    llm = GuardedLLM(ChatOpenAI(model="gpt-4o-mini"))
    response = llm.invoke("Tell me a joke")
"""

from __future__ import annotations

import logging
from typing import Any, List, Optional

# Optional LangChain import - stubs avoid import errors when not installed
try:
    from langchain_core.language_models import BaseChatModel
    from pydantic import PrivateAttr
    _LANGCHAIN_AVAILABLE = True
except ImportError:
    _LANGCHAIN_AVAILABLE = False
    # Fallback stubs so the class definition doesn't blow up at parse time
    BaseChatModel = object  # type: ignore[misc,assignment]
    PrivateAttr = lambda **kw: None  # type: ignore[assignment]  # noqa: E731

from .exceptions import GuardExViolation, PIIViolation
from .guard import _enforce_block
from .policy import GuardExPolicy
# Guard is imported lazily inside __init__ to avoid a circular import at
# module load time (guard.py imports from wrapper indirectly via __init__.py).

logger = logging.getLogger(__name__)


def _require_langchain() -> None:
    """Raise a clear error if LangChain is not installed."""
    if not _LANGCHAIN_AVAILABLE:
        raise ImportError(
            "GuardedLLM requires langchain-core.  Install it with:\n"
            "  pip install 'guardex-ai[langchain]'\n"
            "or directly:\n"
            "  pip install 'langchain-core>=0.1.40,<0.4'"
        )


class GuardedLLM(BaseChatModel):
    """Wraps any ``BaseChatModel`` with server-side PII detection and safety rails.

    Parameters
    ----------
    llm:
        The underlying LangChain chat model (e.g. ``ChatOpenAI``).
    api_key:
        GuardEx API key. Overrides policy.api_key if both are provided.
    policy:
        Optional :class:`~guardex.policy.GuardExPolicy`.

    Raises
    ------
    ImportError
        If ``langchain-core`` is not installed.
    PIIViolation
        If ``pii_action='block'`` and PII is found.
    GuardExViolation
        If content is classified as unsafe.
    """

    if _LANGCHAIN_AVAILABLE:
        _llm: Any = PrivateAttr()
        _policy: GuardExPolicy = PrivateAttr()
        _guard: Any = PrivateAttr()  # Guard instance - handles injection + callbacks
        _debug: bool = PrivateAttr(default=False)
        _debug_printed: bool = PrivateAttr(default=False)

    def __init__(
        self,
        llm: Any,
        api_key: str | None = None,
        policy: GuardExPolicy | None = None,
        guard: Any = None,
        debug: bool = False,
        **kwargs: Any,
    ) -> None:
        _require_langchain()
        super().__init__(**kwargs)
        self._llm = llm
        self._debug = debug
        self._debug_printed = False

        if guard is not None:
            self._guard = guard
            self._policy = guard.policy
        else:
            from .guard import Guard
            self._policy = policy or GuardExPolicy()
            effective_key = api_key or self._policy.api_key
            self._guard = Guard(
                api_key=effective_key,
                base_url=self._policy.base_url,
                policy=self._policy,
                fail_open=self._policy.fail_open,
            )

    @property
    def policy(self) -> GuardExPolicy:
        """The active GuardExPolicy governing input/output screening."""
        return self._policy

    @property
    def _llm_type(self) -> str:
        return f"guarded-{getattr(self._llm, '_llm_type', 'unknown')}"

    def _generate(
        self,
        messages: List[Any],
        stop: Optional[List[str]] = None,
        run_manager: Any = None,
        **kwargs: Any,
    ) -> Any:
        _require_langchain()

        # Lazy import - only needed when actually generating
        from langchain_core.messages import AIMessage, BaseMessage
        from langchain_core.outputs import ChatGeneration, ChatResult

        if self._debug and not self._debug_printed:
            self._debug_printed = True
            try:
                config = self._guard._client.get_effective_config()
                logger.debug("Effective config: %s", config)
            except Exception as exc:
                logger.debug("Could not fetch effective config for debug: %s", exc)

        # Screen each human message individually - concatenating them dilutes
        # the classifier's signal and may miss per-message violations.
        if self._policy.block_on_unsafe_input or self._policy.pii_enabled or self._policy.topic_scope:
            from langchain_core.messages import HumanMessage as _HM

            new_messages = list(messages)
            for idx, msg in enumerate(messages):
                if not (isinstance(msg, BaseMessage) and msg.type == "human"
                        and isinstance(msg.content, str)):
                    continue

                sr = self._guard.screen(msg.content, gate="input")

                # Check topic scope
                if sr.scope and not sr.scope.allowed:
                    reason = sr.scope.reason or "Query is outside the allowed topic scope."
                    logger.warning("GuardedLLM blocked INPUT: out of scope - %s", reason)
                    raise GuardExViolation(stage="input", category="scope", raw_response=reason)

                # Check PII block
                if self._policy.pii_action == "block" and sr.pii.has_pii:
                    raise PIIViolation(
                        stage="input",
                        entities_found=[
                            {"label": e.label, "score": e.score, "start": e.start, "end": e.end}
                            for e in sr.pii.entities
                        ],
                    )

                # Safety-classifier verdict is gated by block_on_unsafe_input;
                # injection and safety routes always enforce.
                if sr.blocked and _enforce_block(sr, "input", self._policy):
                    cat = sr.classify.category
                    logger.warning("GuardedLLM blocked INPUT (msg %d): category=%s", idx, cat)
                    raise GuardExViolation(
                        stage="input", category=cat,
                        description=sr.classify.description,
                    )

                # If PII was masked, replace this message with masked version
                if sr.text != msg.content and self._policy.pii_action == "mask":
                    new_messages[idx] = _HM(content=sr.text)

            messages = new_messages

        inner_result: ChatResult = self._llm._generate(
            messages, stop=stop, run_manager=run_manager, **kwargs
        )

        if self._policy.block_on_unsafe_output or self._policy.pii_enabled:
            for i, gen in enumerate(inner_result.generations):
                raw_text = gen.message.content if isinstance(gen.message.content, str) else ""
                if not raw_text:
                    continue

                sr = self._guard.screen(raw_text, gate="output")

                # Check PII block on output
                if self._policy.pii_action == "block" and sr.pii.has_pii:
                    raise PIIViolation(
                        stage="output",
                        entities_found=[
                            {"label": e.label, "score": e.score, "start": e.start, "end": e.end}
                            for e in sr.pii.entities
                        ],
                    )

                # Safety-classifier verdict is gated by block_on_unsafe_output;
                # safety routes always enforce.
                if sr.blocked and _enforce_block(sr, "output", self._policy):
                    cat = sr.classify.category
                    logger.warning("GuardedLLM blocked OUTPUT: category=%s", cat)
                    raise GuardExViolation(
                        stage="output", category=cat,
                        description=sr.classify.description,
                    )

                # Apply masked text to generation
                if sr.text != raw_text:
                    inner_result.generations[i] = ChatGeneration(
                        message=AIMessage(content=sr.text),
                        generation_info=gen.generation_info,
                    )

        return inner_result

    async def _agenerate(
        self,
        messages: List[Any],
        stop: Optional[List[str]] = None,
        run_manager: Any = None,
        **kwargs: Any,
    ) -> Any:
        """Async version of _generate.

        Mirrors _generate exactly but routes every screening call through
        Guard.ascreen so async LangChain chains do not pay the cost of
        synchronous to_thread bridging at every step.  Local-mode Guards
        already bridge sync work to threads inside ascreen, so the work
        happens off the event loop either way.
        """
        _require_langchain()

        from langchain_core.messages import AIMessage, BaseMessage
        from langchain_core.outputs import ChatGeneration, ChatResult

        if self._debug and not self._debug_printed:
            self._debug_printed = True
            try:
                config = self._guard._client.get_effective_config()
                logger.debug("Effective config: %s", config)
            except Exception as exc:
                logger.debug("Could not fetch effective config for debug: %s", exc)

        if (
            self._policy.block_on_unsafe_input
            or self._policy.pii_enabled
            or self._policy.topic_scope
        ):
            from langchain_core.messages import HumanMessage as _HM

            new_messages = list(messages)
            for idx, msg in enumerate(messages):
                if not (
                    isinstance(msg, BaseMessage)
                    and msg.type == "human"
                    and isinstance(msg.content, str)
                ):
                    continue

                sr = await self._guard.ascreen(msg.content, gate="input")

                if sr.scope and not sr.scope.allowed:
                    reason = sr.scope.reason or "Query is outside the allowed topic scope."
                    logger.warning("GuardedLLM (async) blocked INPUT: out of scope - %s", reason)
                    raise GuardExViolation(stage="input", category="scope", raw_response=reason)

                if self._policy.pii_action == "block" and sr.pii.has_pii:
                    raise PIIViolation(
                        stage="input",
                        entities_found=[
                            {"label": e.label, "score": e.score, "start": e.start, "end": e.end}
                            for e in sr.pii.entities
                        ],
                    )

                # See _generate input-gate comment.
                if sr.blocked and _enforce_block(sr, "input", self._policy):
                    cat = sr.classify.category
                    logger.warning(
                        "GuardedLLM (async) blocked INPUT (msg %d): category=%s", idx, cat
                    )
                    raise GuardExViolation(
                        stage="input", category=cat,
                        description=sr.classify.description,
                    )

                if sr.text != msg.content and self._policy.pii_action == "mask":
                    new_messages[idx] = _HM(content=sr.text)

            messages = new_messages

        # Delegate the actual LLM call.  Most chat models implement
        # _agenerate; fall back to the sync path inside a thread if not.
        if hasattr(self._llm, "_agenerate"):
            inner_result: ChatResult = await self._llm._agenerate(
                messages, stop=stop, run_manager=run_manager, **kwargs
            )
        else:
            import asyncio as _asyncio
            inner_result = await _asyncio.to_thread(
                self._llm._generate, messages, stop=stop, run_manager=run_manager, **kwargs
            )

        if self._policy.block_on_unsafe_output or self._policy.pii_enabled:
            for i, gen in enumerate(inner_result.generations):
                raw_text = gen.message.content if isinstance(gen.message.content, str) else ""
                if not raw_text:
                    continue

                sr = await self._guard.ascreen(raw_text, gate="output")

                if self._policy.pii_action == "block" and sr.pii.has_pii:
                    raise PIIViolation(
                        stage="output",
                        entities_found=[
                            {"label": e.label, "score": e.score, "start": e.start, "end": e.end}
                            for e in sr.pii.entities
                        ],
                    )

                # See _generate output-gate comment.
                if sr.blocked and _enforce_block(sr, "output", self._policy):
                    cat = sr.classify.category
                    logger.warning("GuardedLLM (async) blocked OUTPUT: category=%s", cat)
                    raise GuardExViolation(
                        stage="output", category=cat,
                        description=sr.classify.description,
                    )

                if sr.text != raw_text:
                    inner_result.generations[i] = ChatGeneration(
                        message=AIMessage(content=sr.text),
                        generation_info=gen.generation_info,
                    )

        return inner_result
