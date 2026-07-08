# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 GuardEx
"""Reversible PII tokenisation with de-masking.

``guard.pii_mask()`` replaces PII with ``[EMAIL]`` / ``[SSN]`` style
tags. The original values are lost - useful for screening, useless when
the LLM needs to echo the value back ("send a confirmation to ...").

``PIIVault`` keeps a per-session map from random tokens to original PII.
The LLM sees ``{{pii:email:a3f9}}``; ``vault.restore(response)``
substitutes the real values back in before the user sees the response.

Flow::

    vault = PIIVault()
    pii_result = guard.pii_scan(user_text)
    vaulted_text, vault = vault.vault_text(user_text, pii_result)
    llm_response = llm.invoke(vaulted_text)
    final_response = vault.restore(llm_response)

Token format: ``{{pii:<LABEL>:<32-hex-chars>}}``,
e.g. ``{{pii:email:3a7f09b1c2d4e6f8a0b1c2d3e4f5a6b7}}``.
"""

from __future__ import annotations

import re
import secrets
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple


# Token pattern used both when inserting and when restoring (32 hex = 128 bits)
_TOKEN_RE = re.compile(r"\{\{pii:([a-z0-9_]+):([0-9a-f]{32})\}\}")


@dataclass
class VaultEntry:
    """A single PII token-to-value mapping stored inside a :class:`PIIVault`.

    Attributes
    ----------
    token:
        Full token string inserted into text, e.g. ``{{pii:email:3a7f09b1...}}``.
    label:
        PII entity type, e.g. ``email``, ``ssn``, ``phone_number``.
    original:
        The original PII text that was replaced by the token.
    """
    token: str
    label: str
    original: str


class PIIVault:
    """Per-session store that maps vault tokens to original PII values.

    Thread-safety: NOT thread-safe by default.  For concurrent use, create
    one ``PIIVault`` per request or protect with a lock.

    Parameters
    ----------
    max_entries : int
        Maximum number of entries (default 1 000).  Prevents unbounded growth
        in long-running processes.
    """

    SYSTEM_PROMPT_HINT: str = (
        "Some values in this conversation have been replaced with privacy "
        "tokens in the format {{pii:TYPE:ID}} (e.g. {{pii:name:a3f2...}}, "
        "{{pii:email:b7c4...}}). These represent real user data that has been "
        "redacted for privacy. Treat each token as if it were the actual value "
        "— use them naturally in your response exactly as they appear. They "
        "will be automatically restored to real values before the user sees "
        "your reply. Never ask the user to provide information that is already "
        "represented by a token."
    )
    """System prompt snippet that teaches LLMs to use vault tokens naturally.

    Include this in your system message when sending vaulted text to any LLM::

        messages = [
            {"role": "system", "content": f"You are a support agent. {PIIVault.SYSTEM_PROMPT_HINT}"},
            {"role": "user", "content": vaulted_input},
        ]
    """

    def __init__(self, max_entries: int = 1_000) -> None:
        self._store: Dict[str, VaultEntry] = {}
        self._max_entries = max_entries

    # Public API

    def vault_text(
        self,
        text: str,
        pii_result,  # PIIResult from guard.pii_scan() / guard.screen()
    ) -> Tuple[str, "PIIVault"]:
        """Replace PII spans in *text* with vault tokens.

        Processes entities in **reverse span order** so that earlier offsets
        remain valid as we substitute later ones first.

        Parameters
        ----------
        text:
            The original text containing PII.
        pii_result:
            A :class:`~guardex._types.PIIResult` returned by
            ``guard.pii_scan()`` or ``guard.screen().pii``.

        Returns
        -------
        tuple[str, PIIVault]
            ``(vaulted_text, self)`` - the same vault instance is returned for
            chaining convenience.

        Examples
        --------
        >>> vaulted, vault = PIIVault().vault_text(text, pii)
        >>> response = llm.invoke(vaulted)
        >>> safe_response = vault.restore(response)
        """
        if not pii_result.entities:
            return text, self

        # Sort entities by span start descending so substitutions don't shift offsets
        entities = sorted(pii_result.entities, key=lambda e: e.start, reverse=True)

        result = text
        for entity in entities:
            # Fall back to span extraction when server returns empty text
            original_text = entity.text or text[entity.start : entity.end]
            token_str = self._make_token(entity.label, original_text)
            result = result[: entity.start] + token_str + result[entity.end :]

        return result, self

    def restore(self, text: str) -> str:
        """Replace all vault tokens in *text* with their original values.

        Tokens not found in this vault are left unchanged (safe for multi-vault
        or partial text scenarios).

        Parameters
        ----------
        text:
            Text (typically an LLM response) that may contain vault tokens.

        Returns
        -------
        str
            Text with tokens replaced by original PII values.
        """
        def _replace(match: re.Match) -> str:
            token_str = match.group(0)
            entry = self._store.get(token_str)
            return entry.original if entry else token_str

        return _TOKEN_RE.sub(_replace, text)

    def get_original(self, token: str) -> Optional[str]:
        """Return the original PII value for a token, or ``None`` if unknown."""
        entry = self._store.get(token)
        return entry.original if entry else None

    def entries(self) -> List[VaultEntry]:
        """Return all stored vault entries (for audit / logging)."""
        return list(self._store.values())

    def clear(self) -> None:
        """Wipe the vault - call after the session is complete."""
        self._store.clear()

    def __len__(self) -> int:
        return len(self._store)

    def __repr__(self) -> str:
        return f"PIIVault(entries={len(self._store)}, max={self._max_entries})"

    # Private helpers

    def _make_token(self, label: str, original: str) -> str:
        """Create a token and store the mapping; return token string."""
        # Check if this exact original value already has a token (dedup)
        for entry in self._store.values():
            if entry.label == label and entry.original == original:
                return entry.token

        if len(self._store) >= self._max_entries:
            raise RuntimeError(
                f"PIIVault is full ({self._max_entries} entries).  "
                "Call vault.clear() between sessions or increase max_entries."
            )

        hex_id = secrets.token_hex(16)  # 32 hex chars = 128 bits
        token_str = f"{{{{pii:{label.lower()}:{hex_id}}}}}"
        entry = VaultEntry(token=token_str, label=label, original=original)
        self._store[token_str] = entry
        return token_str
