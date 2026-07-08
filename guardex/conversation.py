# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 GuardEx
"""ConversationGuard - multi-turn conversation-aware screening.

Problem solved
--------------
``Guard.screen()`` is stateless - every call is independent.  An attacker can
use **incremental escalation**: spread harmful content across 5-6 turns so that
no single turn looks unsafe in isolation.

Solution
--------
``ConversationGuard`` wraps ``Guard`` and maintains a per-session sliding window
of recent conversation turns.  When screening new input, it prepends the recent
history to the text so the classifier sees the full escalation pattern.

Usage::

    from guardex import Guard
    from guardex.conversation import ConversationGuard, Turn

    guard = Guard()
    cg = ConversationGuard(guard, window=6)

    # Screen each turn - history is managed automatically
    result = cg.screen_turn("user", user_message)
    if result.blocked:
        return "I can't help with that."

    llm_reply = llm.invoke(user_message)

    # Record the assistant reply too (screens it and adds to history)
    result = cg.screen_turn("assistant", llm_reply)
    ...

    # Reset at session end
    cg.reset()

Async support::

    result = await cg.ascreen_turn("user", user_message)
"""

from __future__ import annotations

import logging
from collections import deque
from dataclasses import dataclass
from typing import Deque, Literal

logger = logging.getLogger(__name__)

Role = Literal["user", "assistant", "system"]


@dataclass
class Turn:
    """A single conversation turn."""
    role: Role
    content: str

    def to_text(self) -> str:
        """Format the turn as a labeled string, e.g. ``[USER] Hello``."""
        return f"[{self.role.upper()}] {self.content}"


class ConversationGuard:
    """Stateful, multi-turn wrapper around :class:`~guardex.guard.Guard`.

    Parameters
    ----------
    guard : Guard
        The underlying Guard instance to delegate screening to.
    window : int
        Number of past turns to include when screening new content (default 6).
        Higher values catch longer escalation chains at the cost of larger
        payloads sent to the API.
    screen_assistant_turns : bool
        When True (default), assistant responses are also screened and stored
        in history.  Set to False for output-only screening if you already call
        ``guard.screen()`` on the output separately.
    separator : str
        Separator string used when concatenating turns into a single text block.
    """

    def __init__(
        self,
        guard,                            # Guard - avoid circular import
        window: int = 6,
        screen_assistant_turns: bool = True,
        separator: str = "\n",
        max_payload_chars: int = 16_000,
    ) -> None:
        self._guard = guard
        self._window = window
        self._screen_assistant = screen_assistant_turns
        self._separator = separator
        self._max_payload = max_payload_chars
        self._history: Deque[Turn] = deque(maxlen=window)

    # Public API

    def screen_turn(
        self,
        role: Role,
        content: str,
        context=None,  # Optional[GuardExContext] - avoid circular import
    ):
        """Screen a single turn with full conversation history context.

        The history of the last ``window`` turns is prepended to *content*
        before screening, so the classifier sees the full conversation arc.

        After a successful screen the turn is added to history.

        Parameters
        ----------
        role:
            ``"user"``, ``"assistant"``, or ``"system"``.
        content:
            The turn text.
        context:
            Optional :class:`~guardex.context.GuardExContext`.

        Returns
        -------
        ScreenResult
        """
        if role == "user":
            gate = "input"
        elif role == "system":
            gate = "prompt"
        else:
            gate = "output"
        text_to_screen = self._build_payload(content)

        result = self._guard.screen(text_to_screen, gate=gate, context=context)

        # Store the ORIGINAL content in history (not the concatenated payload)
        if not result.blocked:
            if role == "user" or self._screen_assistant:
                self._history.append(Turn(role=role, content=content))
        else:
            logger.warning(
                "ConversationGuard blocked %s turn at turn %d: category=%s",
                role, len(self._history) + 1, result.classify.category,
            )

        return result

    async def ascreen_turn(
        self,
        role: Role,
        content: str,
        context=None,
    ):
        """Async version of :meth:`screen_turn`."""
        if role == "user":
            gate = "input"
        elif role == "system":
            gate = "prompt"
        else:
            gate = "output"
        text_to_screen = self._build_payload(content)

        result = await self._guard.ascreen(text_to_screen, gate=gate, context=context)

        if not result.blocked:
            if role == "user" or self._screen_assistant:
                self._history.append(Turn(role=role, content=content))
        else:
            logger.warning(
                "ConversationGuard blocked async %s turn: category=%s",
                role, result.classify.category,
            )

        return result

    def add_turn(self, role: Role, content: str) -> None:
        """Add a turn to history WITHOUT screening it.

        Use this for turns that have already been screened externally, or for
        system prompts that don't need to go through the guardrails API.
        """
        self._history.append(Turn(role=role, content=content))

    def reset(self) -> None:
        """Clear conversation history.  Call at session end."""
        self._history.clear()

    @property
    def history(self) -> list[Turn]:
        """Current conversation history (oldest first)."""
        return list(self._history)

    @property
    def turn_count(self) -> int:
        """Number of turns currently in the window."""
        return len(self._history)

    def __repr__(self) -> str:
        return (
            f"ConversationGuard(window={self._window}, "
            f"turns={len(self._history)})"
        )

    # Private helpers

    def _build_payload(self, new_content: str) -> str:
        """Concatenate history + new content into a single screening payload.

        Respects ``max_payload_chars`` by truncating oldest history turns
        first (newest context is most relevant for escalation detection).
        """
        if not self._history:
            return new_content

        parts = [t.to_text() for t in self._history]
        parts.append(new_content)
        payload = self._separator.join(parts)

        # Truncate from the front (oldest turns) if over budget
        while len(payload) > self._max_payload and len(parts) > 1:
            parts.pop(0)
            payload = self._separator.join(parts)

        return payload
