# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 GuardEx
"""GuardExCallbackHandler - plug safety into any existing LangChain chain.

Usage::

    from guardex import GuardExCallbackHandler
    from langchain_openai import ChatOpenAI

    handler = GuardExCallbackHandler()
    llm = ChatOpenAI(model="gpt-4o-mini", callbacks=[handler])
    llm.invoke([HumanMessage(content="Hello!")])

.. note::

   **PII masking limitation in the callback handler:**
   By the time ``on_chat_model_start`` fires, the prompt is already built by
   LangChain and cannot be modified.  Therefore:

   * ``pii_action='mask'`` on input -> logs a warning but cannot rewrite the prompt.
     Use :class:`~guardex.wrapper.GuardedLLM` if you need input masking.
   * ``pii_action='block'`` on input -> raises :class:`PIIViolation` as expected.
   * PII masking on **output** works fully in both modes.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional
from uuid import UUID

try:
    from langchain_core.callbacks import BaseCallbackHandler
    from langchain_core.messages import AIMessage, BaseMessage
    from langchain_core.outputs import LLMResult
    _LANGCHAIN_AVAILABLE = True
except ImportError:
    _LANGCHAIN_AVAILABLE = False
    BaseCallbackHandler = object  # type: ignore[assignment,misc]

from .exceptions import GuardExViolation, PIIViolation
from .guard import _enforce_block
from .policy import GuardExPolicy
# Guard is imported lazily inside __init__ to avoid a circular import at
# module load time (guard.py is reachable from __init__.py before handler).

logger = logging.getLogger(__name__)


class GuardExCallbackHandler(BaseCallbackHandler):
    """LangChain callback handler that screens LLM inputs and outputs through a Guard (in-process by default).

    Parameters
    ----------
    api_key:
        GuardEx API key. Overrides policy.api_key if both are provided.
    policy:
        Optional :class:`~guardex.policy.GuardExPolicy`.

    Raises
    ------
    PIIViolation
        When ``pii_action='block'`` and PII is detected.
    GuardExViolation
        When content is classified as unsafe.
    """

    raise_error: bool = True

    def __init__(
        self,
        api_key: str | None = None,
        policy: GuardExPolicy | None = None,
        debug: bool = False,
    ) -> None:
        if not _LANGCHAIN_AVAILABLE:
            raise ImportError(
                "GuardExCallbackHandler requires langchain-core. "
                "Install it with: pip install 'guardex-ai[langchain]'"
            )
        super().__init__()
        self.policy = policy or GuardExPolicy()
        self._debug = debug
        self._debug_printed = False

        effective_key = api_key or self.policy.api_key
        # Route through Guard so mode selection (local vs server), injection
        # detection, and safety routes match the rest of the SDK.
        from .guard import Guard
        self._guard = Guard(
            api_key=effective_key,
            policy=self.policy,
            fail_open=self.policy.fail_open,
        )

    def _screen_input(self, text: str) -> None:
        """Screen input text through the configured Guard."""
        if not text.strip():
            return

        # Debug: log effective config on first call
        if self._debug and not self._debug_printed:
            self._debug_printed = True
            try:
                config = self._guard._client.get_effective_config()
                logger.debug("Effective config: %s", config)
            except Exception as exc:
                logger.debug("Could not fetch effective config for debug: %s", exc)

        sr = self._guard.screen(text, gate="input")

        # Check topic scope
        if sr.scope and not sr.scope.allowed:
            reason = sr.scope.reason or "Query is outside the allowed topic scope."
            logger.warning("CallbackHandler blocked INPUT: out of scope - %s", reason)
            raise GuardExViolation(stage="input", category="scope", raw_response=reason)

        if self.policy.pii_enabled and sr.pii.has_pii:
            if self.policy.pii_action == "block":
                raise PIIViolation(
                    stage="input",
                    entities_found=[
                        {"label": e.label, "score": e.score, "start": e.start, "end": e.end}
                        for e in sr.pii.entities
                    ],
                )
            # The prompt is already built by LangChain - masked text cannot
            # be substituted back here. See the module docstring.
            types = sorted({e.label for e in sr.pii.entities})
            logger.warning(
                "PII detected in input (callback handler cannot mask - "
                "use GuardedLLM for input masking): %s",
                types,
            )

        # Safety-classifier verdict is gated by block_on_unsafe_input;
        # injection and safety routes always enforce.
        if sr.blocked and _enforce_block(sr, "input", self.policy):
            cat = sr.classify.category
            logger.warning("CallbackHandler blocked INPUT: category=%s", cat)
            raise GuardExViolation(
                stage="input", category=cat,
                description=sr.classify.description,
            )

    def on_llm_start(
        self,
        serialized: Dict[str, Any],
        prompts: List[str],
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        **kwargs: Any,
    ) -> None:
        """Called before the LLM receives raw string prompts.

        Screens each prompt individually so a single unsafe prompt in a
        batch raises immediately instead of being diluted by joining.
        """
        for prompt in prompts:
            if isinstance(prompt, str) and prompt.strip():
                self._screen_input(prompt)

    def on_chat_model_start(
        self,
        serialized: Dict[str, Any],
        messages: List[List[BaseMessage]],
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        **kwargs: Any,
    ) -> None:
        """Called before a *chat* model receives structured messages.

        Screens each message individually to preserve classifier signal
        on a per-message basis.
        """
        for batch in messages:
            for msg in batch:
                content = getattr(msg, "content", None)
                if isinstance(content, str) and content.strip():
                    self._screen_input(content)

    def on_llm_end(
        self,
        response: LLMResult,
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        **kwargs: Any,
    ) -> None:
        """Called after the LLM returns its response."""
        for generation_list in response.generations:
            for generation in generation_list:
                if hasattr(generation, "message"):
                    reply_msg = generation.message
                    raw_text = reply_msg.content if isinstance(reply_msg.content, str) else ""
                else:
                    raw_text = str(generation.text)
                    reply_msg = AIMessage(content=raw_text)

                if not raw_text:
                    continue

                sr = self._guard.screen(raw_text, gate="output")

                # PII block on output
                if self.policy.pii_action == "block" and sr.pii.has_pii:
                    raise PIIViolation(
                        stage="output",
                        entities_found=[
                            {"label": e.label, "score": e.score, "start": e.start, "end": e.end}
                            for e in sr.pii.entities
                        ],
                    )

                # PII masking on output - patch both the message and the
                # generation's text field (completion-style consumers read
                # generation.text, not generation.message).
                screened_text = sr.text
                if screened_text != raw_text:
                    masked = False
                    if hasattr(reply_msg, "content"):
                        try:
                            object.__setattr__(reply_msg, "content", screened_text)
                            masked = True
                        except (AttributeError, TypeError):
                            masked = False
                    try:
                        object.__setattr__(generation, "text", screened_text)
                        masked = True
                    except (AttributeError, TypeError):
                        pass
                    if not masked:
                        # Fail closed: delivering unmasked PII because the
                        # generation object rejected mutation would silently
                        # void the masking guarantee.
                        raise GuardExViolation(
                            stage="output",
                            category="pii",
                            description=(
                                "PII masking could not be applied to the "
                                "generation object; blocking instead of "
                                "returning unmasked output."
                            ),
                        )

                # Safety-classifier verdict is gated by block_on_unsafe_output;
                # safety routes always enforce.
                if sr.blocked and _enforce_block(sr, "output", self.policy):
                    cat = sr.classify.category
                    logger.warning("CallbackHandler blocked OUTPUT: category=%s", cat)
                    raise GuardExViolation(
                        stage="output", category=cat,
                        description=sr.classify.description,
                    )

    def on_llm_error(
        self,
        error: BaseException,
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        **kwargs: Any,
    ) -> None:
        """Called when the LLM raises an error. Logs the error and passes through."""
        logger.error("LLM error (not from GuardEx): %s", error)
