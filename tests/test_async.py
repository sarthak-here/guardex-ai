"""Tests for async variants: Guard.ascreen, ascreen_or_raise, astream.

Uses respx for HTTP mocking and pytest-asyncio for async test execution.
"""

from __future__ import annotations

from typing import AsyncIterator
from unittest.mock import AsyncMock

import pytest
import respx
import httpx

from guardex.guard import Guard
from guardex.stream import AsyncStreamGuard
from guardex.policy import GuardExPolicy
from guardex.exceptions import GuardExViolation

from tests.helpers import (
    SAFE_SCREEN_RESPONSE,
    UNSAFE_SCREEN_RESPONSE,
    PII_MASKED_SCREEN_RESPONSE,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_safe_response(text: str) -> dict:
    return {
        "pii": {"has_pii": False, "entities": []},
        "classify": {"safe": True, "category": None, "categories": []},
        "text": text,
    }


def _make_unsafe_response() -> dict:
    return {
        "pii": {"has_pii": False, "entities": []},
        "classify": {"safe": False, "category": "S9", "categories": ["S9"]},
        "text": "blocked",
    }


def _default_policy() -> GuardExPolicy:
    return GuardExPolicy(api_key="gx_test_x", base_url="http://localhost:8001")


async def _async_chunks(items: list[str]) -> AsyncIterator[str]:
    for item in items:
        yield item


# ---------------------------------------------------------------------------
# Guard.ascreen()
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestAsyncScreen:
    async def test_safe_content(self, guard: Guard) -> None:
        with respx.mock(base_url="http://localhost:8001") as router:
            router.post("/v1/screen").respond(json=SAFE_SCREEN_RESPONSE)

            result = await guard.ascreen("Hello world", gate="input")
            assert result.safe is True
            assert result.blocked is False
            assert result.gate == "input"
            assert result.latency_ms > 0

    async def test_unsafe_content(self, guard: Guard) -> None:
        with respx.mock(base_url="http://localhost:8001") as router:
            router.post("/v1/screen").respond(json=UNSAFE_SCREEN_RESPONSE)

            result = await guard.ascreen("bad content", gate="input")
            assert result.blocked is True
            assert result.classify.category == "S9"

    async def test_pii_masked(self, guard: Guard) -> None:
        with respx.mock(base_url="http://localhost:8001") as router:
            router.post("/v1/screen").respond(json=PII_MASKED_SCREEN_RESPONSE)

            result = await guard.ascreen("My SSN is 123-45-6789", gate="input")
            assert result.action == "mask"
            assert result.text == "My SSN is [SSN]"

    async def test_fail_open(self, guard_fail_open: Guard) -> None:
        with respx.mock(base_url="http://localhost:8001") as router:
            router.post("/v1/screen").mock(
                side_effect=httpx.ConnectError("Connection refused")
            )

            result = await guard_fail_open.ascreen("test", gate="input")
            assert result.safe is True
            assert result.action == "pass"


# ---------------------------------------------------------------------------
# Guard.ascreen_or_raise()
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestAsyncScreenOrRaise:
    async def test_safe_returns_text(self, guard: Guard) -> None:
        with respx.mock(base_url="http://localhost:8001") as router:
            router.post("/v1/screen").respond(json=SAFE_SCREEN_RESPONSE)

            text = await guard.ascreen_or_raise("Hello world", gate="input")
            assert text == "Hello world"

    async def test_unsafe_raises(self, guard: Guard) -> None:
        with respx.mock(base_url="http://localhost:8001") as router:
            router.post("/v1/screen").respond(json=UNSAFE_SCREEN_RESPONSE)

            with pytest.raises(GuardExViolation) as exc_info:
                await guard.ascreen_or_raise("bad", gate="input")

            assert exc_info.value.stage == "input"
            assert exc_info.value.category == "S9"

    async def test_masked_returns_masked_text(self, guard: Guard) -> None:
        with respx.mock(base_url="http://localhost:8001") as router:
            router.post("/v1/screen").respond(json=PII_MASKED_SCREEN_RESPONSE)

            text = await guard.ascreen_or_raise("My SSN is 123-45-6789", gate="input")
            assert text == "My SSN is [SSN]"


# ---------------------------------------------------------------------------
# AsyncStreamGuard (direct, no HTTP)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestAsyncStreamGuard:
    async def test_safe_stream(self) -> None:
        client = AsyncMock()
        client.screen = AsyncMock(return_value=(_make_safe_response("hello world"), None))

        sg = AsyncStreamGuard(client, _default_policy(), gate="output", flush_every=256)
        result = []
        async for chunk in sg.run(_async_chunks(["hello world"])):
            result.append(chunk)

        assert result == ["hello world"]

    async def test_unsafe_raises(self) -> None:
        client = AsyncMock()
        client.screen = AsyncMock(return_value=(_make_unsafe_response(), None))

        sg = AsyncStreamGuard(client, _default_policy(), gate="output", flush_every=10)

        with pytest.raises(GuardExViolation) as exc_info:
            async for _ in sg.run(_async_chunks(["x" * 15])):
                pass

        assert exc_info.value.category == "S9"

    async def test_flush_at_threshold(self) -> None:
        responses = [
            (_make_safe_response("aaaaaaaaaa"), None),
            (_make_safe_response("bbbbb"), None),
        ]
        client = AsyncMock()
        client.screen = AsyncMock(side_effect=responses)

        sg = AsyncStreamGuard(client, _default_policy(), gate="output", flush_every=10)
        result = []
        async for chunk in sg.run(_async_chunks(["a" * 10, "b" * 5])):
            result.append(chunk)

        assert len(result) == 2
        assert client.screen.call_count == 2

    async def test_fail_open_passes_through(self) -> None:
        client = AsyncMock()
        client.screen = AsyncMock(return_value=({"_fail_open": True}, None))

        sg = AsyncStreamGuard(client, _default_policy(), gate="output", flush_every=256)
        result = []
        async for chunk in sg.run(_async_chunks(["hello"])):
            result.append(chunk)

        assert result == ["hello"]

    async def test_out_of_scope_buffer_blocks(self) -> None:
        """Scope verdict (separate from classify.safe) must block the async stream."""
        out_of_scope = {
            "pii": {"has_pii": False, "entities": []},
            "classify": {"safe": True, "category": None, "categories": []},
            "scope": {"allowed": False, "reason": "off-topic", "matched_topic": None},
            "text": "weather chat",
        }
        client = AsyncMock()
        client.screen = AsyncMock(return_value=(out_of_scope, None))

        sg = AsyncStreamGuard(client, _default_policy(), gate="output", flush_every=256)
        with pytest.raises(GuardExViolation) as exc:
            async for _ in sg.run(_async_chunks(["what's the weather like today"])):
                pass
        assert exc.value.category == "scope"


# ---------------------------------------------------------------------------
# Guard.astream() integration
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestGuardAstream:
    async def test_astream_safe(self, guard: Guard) -> None:
        with respx.mock(base_url="http://localhost:8001") as router:
            router.post("/v1/screen").respond(json=SAFE_SCREEN_RESPONSE)

            result = []
            async for chunk in guard.astream(_async_chunks(["Hello world"]), gate="output"):
                result.append(chunk)

            assert len(result) >= 1

    async def test_astream_unsafe_raises(self, guard: Guard) -> None:
        with respx.mock(base_url="http://localhost:8001") as router:
            router.post("/v1/screen").respond(json=UNSAFE_SCREEN_RESPONSE)

            with pytest.raises(GuardExViolation):
                async for _ in guard.astream(
                    _async_chunks(["x" * 300]), gate="output", flush_every=10
                ):
                    pass

    async def test_local_astream_output_pii_uses_stream_flag(self) -> None:
        class LocalRunner:
            def __init__(self) -> None:
                self.calls = []

            def screen(self, **kwargs):
                self.calls.append(kwargs)
                return _make_safe_response(kwargs["text"]), "local-request"

        runner = LocalRunner()
        guard = Guard.__new__(Guard)
        guard._policy = GuardExPolicy(pii_action="block")
        guard._client = runner
        guard._injection_detector = None

        result = []
        async for chunk in guard.astream(
            _async_chunks(["email alice@example.com"]),
            gate="output",
        ):
            result.append(chunk)

        assert result == ["email alice@example.com"]
        assert runner.calls[0]["pii_action"] == "none"


# ---------------------------------------------------------------------------
# Guard async lifecycle
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestGuardAsyncLifecycle:
    async def test_async_context_manager(self, api_key: str, base_url: str) -> None:
        async with Guard(api_key=api_key, base_url=base_url) as g:
            assert isinstance(g, Guard)
