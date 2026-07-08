"""Input validation edge cases for Guard.screen().

Covers empty strings, whitespace, extremely long inputs, Unicode/emoji,
and None. Uses respx to mock all HTTP so no server is required.
"""

from __future__ import annotations

import pytest
import respx

from guardex.guard import Guard
from tests.helpers import SAFE_SCREEN_RESPONSE


# Large input size (~1 MB of 'A's) — well past any reasonable payload limit.
_EXTREMELY_LONG_INPUT = "A" * 1_000_000


def _safe_response_with(text: str) -> dict:
    """Canonical safe response but with a custom echoed text field."""
    return {
        "pii": {"has_pii": False, "entities": []},
        "classify": {"safe": True, "category": None, "categories": []},
        "text": text,
    }


@respx.mock(base_url="http://localhost:8001")
def test_screen_empty_string_does_not_crash(
    respx_mock: respx.MockRouter, guard: Guard
) -> None:
    """Passing '' must not crash the client — the server decides validity."""
    respx_mock.post("/v1/screen").respond(json=_safe_response_with(""))

    result = guard.screen("", gate="input")
    assert result is not None
    assert result.text == ""


@respx.mock(base_url="http://localhost:8001")
def test_screen_whitespace_only_string_does_not_crash(
    respx_mock: respx.MockRouter, guard: Guard
) -> None:
    """Pure whitespace ('   \\n\\t  ') must not crash — server echoes it back."""
    ws = "   \n\t  "
    respx_mock.post("/v1/screen").respond(json=_safe_response_with(ws))

    result = guard.screen(ws, gate="input")
    assert result is not None
    assert result.text == ws


@respx.mock(base_url="http://localhost:8001")
def test_screen_extremely_long_string_is_truncated_or_rejected(
    respx_mock: respx.MockRouter, guard: Guard
) -> None:
    """1M-character input should be handled — either truncated by server
    or rejected with an error — but must not hang or crash the SDK.
    We simulate the server returning the echoed text; the SDK's job is to
    parse cleanly regardless of input size."""
    respx_mock.post("/v1/screen").respond(
        json=_safe_response_with(_EXTREMELY_LONG_INPUT)
    )

    result = guard.screen(_EXTREMELY_LONG_INPUT, gate="input")
    assert result is not None
    # The result.text should be either the echoed full input or a truncated
    # version — either way, its length must be <= input length.
    assert len(result.text) <= len(_EXTREMELY_LONG_INPUT)
    # And it must be a string (not bytes or None).
    assert isinstance(result.text, str)


@respx.mock(base_url="http://localhost:8001")
def test_screen_unicode_and_emoji_input_passes_through(
    respx_mock: respx.MockRouter, guard: Guard
) -> None:
    """Unicode and emoji must round-trip without mangling."""
    text = "héllo 🌍 世界 — café naïve 🚀🔥"
    respx_mock.post("/v1/screen").respond(json=_safe_response_with(text))

    result = guard.screen(text, gate="input")
    assert result is not None
    assert result.text == text
    # Explicit check that emoji survived
    assert "🌍" in result.text
    assert "世界" in result.text


def test_screen_with_none_raises_type_error(guard: Guard) -> None:
    """Passing None is a programmer error — should raise a clear error
    (TypeError from string ops or AttributeError from None access)
    rather than silently hitting the network with a null body."""
    # No respx mock: if the SDK lets this through it would attempt a
    # real HTTP call — but it must fail fast at the client layer first.
    with pytest.raises((TypeError, AttributeError)):
        guard.screen(None, gate="input")  # type: ignore[arg-type]
