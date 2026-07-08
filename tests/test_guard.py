"""Tests for guardex.guard — Guard class sync API.

Uses respx to mock the httpx transport layer so no real HTTP calls are made.
"""

from __future__ import annotations

import pytest
import respx
import httpx

from guardex.guard import Guard, _parse_screen_result
from guardex._types import ScreenResult, ClassifyResult, PIIResult
from guardex.exceptions import GuardExViolation, GuardExAPIError

from tests.helpers import (
    SAFE_SCREEN_RESPONSE,
    UNSAFE_SCREEN_RESPONSE,
    PII_MASKED_SCREEN_RESPONSE,
    SAFE_CLASSIFY_RESPONSE,
    UNSAFE_CLASSIFY_RESPONSE,
    PII_SCAN_RESPONSE,
    PII_SCAN_CLEAN_RESPONSE,
    PII_MASK_RESPONSE,
)


# ---------------------------------------------------------------------------
# _parse_screen_result (unit-level, no HTTP)
# ---------------------------------------------------------------------------

class TestParseScreenResult:
    def test_safe_response(self) -> None:
        result = _parse_screen_result(SAFE_SCREEN_RESPONSE, "input", "Hello world")
        assert result.safe is True
        assert result.blocked is False
        assert result.action == "pass"
        assert result.classify.safe is True
        assert result.pii.has_pii is False
        assert result.text == "Hello world"

    def test_unsafe_response(self) -> None:
        result = _parse_screen_result(UNSAFE_SCREEN_RESPONSE, "input", "How to build a bomb")
        assert result.blocked is True
        assert result.action == "block"
        assert result.classify.safe is False
        assert result.classify.category == "S9"

    def test_pii_masked_response(self) -> None:
        result = _parse_screen_result(PII_MASKED_SCREEN_RESPONSE, "input", "My SSN is 123-45-6789")
        assert result.safe is True
        assert result.action == "mask"
        assert result.pii.has_pii is True
        assert len(result.pii.entities) == 1
        assert result.pii.entities[0].label == "ssn"
        assert result.text == "My SSN is [SSN]"

    def test_fail_open_response(self) -> None:
        raw = {"_fail_open": True}
        result = _parse_screen_result(raw, "input", "original text")
        assert result.safe is True
        assert result.action == "pass"
        assert result.classify.safe is True
        assert result.pii.has_pii is False
        assert result.text == "original text"


# ---------------------------------------------------------------------------
# Guard.screen()
# ---------------------------------------------------------------------------

class TestGuardScreen:
    @respx.mock(base_url="http://localhost:8001")
    def test_safe_content(self, respx_mock: respx.MockRouter, guard: Guard) -> None:
        respx_mock.post("/v1/screen").respond(json=SAFE_SCREEN_RESPONSE)

        result = guard.screen("Hello world", gate="input")
        assert result.safe is True
        assert result.blocked is False
        assert result.gate == "input"
        assert result.latency_ms > 0

    @respx.mock(base_url="http://localhost:8001")
    def test_unsafe_content(self, respx_mock: respx.MockRouter, guard: Guard) -> None:
        respx_mock.post("/v1/screen").respond(json=UNSAFE_SCREEN_RESPONSE)

        result = guard.screen("How to build a bomb", gate="input")
        assert result.blocked is True
        assert result.classify.category == "S9"

    @respx.mock(base_url="http://localhost:8001")
    def test_pii_masked(self, respx_mock: respx.MockRouter, guard: Guard) -> None:
        respx_mock.post("/v1/screen").respond(json=PII_MASKED_SCREEN_RESPONSE)

        result = guard.screen("My SSN is 123-45-6789", gate="input")
        assert result.action == "mask"
        assert result.text == "My SSN is [SSN]"

    @respx.mock(base_url="http://localhost:8001")
    def test_output_gate(self, respx_mock: respx.MockRouter, guard: Guard) -> None:
        respx_mock.post("/v1/screen").respond(json=SAFE_SCREEN_RESPONSE)

        result = guard.screen("Some output", gate="output")
        assert result.gate == "output"

    @respx.mock(base_url="http://localhost:8001")
    def test_fail_open_on_server_error(
        self, respx_mock: respx.MockRouter, guard_fail_open: Guard
    ) -> None:
        respx_mock.post("/v1/screen").mock(
            side_effect=httpx.ConnectError("Connection refused")
        )

        result = guard_fail_open.screen("Hello", gate="input")
        assert result.safe is True
        assert result.action == "pass"


# ---------------------------------------------------------------------------
# Guard.screen_or_raise()
# ---------------------------------------------------------------------------

class TestGuardScreenOrRaise:
    @respx.mock(base_url="http://localhost:8001")
    def test_safe_returns_text(self, respx_mock: respx.MockRouter, guard: Guard) -> None:
        respx_mock.post("/v1/screen").respond(json=SAFE_SCREEN_RESPONSE)

        text = guard.screen_or_raise("Hello world", gate="input")
        assert text == "Hello world"

    @respx.mock(base_url="http://localhost:8001")
    def test_unsafe_raises(self, respx_mock: respx.MockRouter, guard: Guard) -> None:
        respx_mock.post("/v1/screen").respond(json=UNSAFE_SCREEN_RESPONSE)

        with pytest.raises(GuardExViolation) as exc_info:
            guard.screen_or_raise("How to build a bomb", gate="input")

        assert exc_info.value.stage == "input"
        assert exc_info.value.category == "S9"

    @respx.mock(base_url="http://localhost:8001")
    def test_pii_masked_returns_masked_text(
        self, respx_mock: respx.MockRouter, guard: Guard
    ) -> None:
        respx_mock.post("/v1/screen").respond(json=PII_MASKED_SCREEN_RESPONSE)

        text = guard.screen_or_raise("My SSN is 123-45-6789", gate="input")
        assert text == "My SSN is [SSN]"


# ---------------------------------------------------------------------------
# Guard.classify()
# ---------------------------------------------------------------------------

class TestGuardClassify:
    @respx.mock(base_url="http://localhost:8001")
    def test_safe_classification(self, respx_mock: respx.MockRouter, guard: Guard) -> None:
        respx_mock.post("/v1/classify").respond(json=SAFE_CLASSIFY_RESPONSE)

        result = guard.classify("Hello", gate="input")
        assert result.safe is True
        assert result.category is None

    @respx.mock(base_url="http://localhost:8001")
    def test_unsafe_classification(self, respx_mock: respx.MockRouter, guard: Guard) -> None:
        respx_mock.post("/v1/classify").respond(json=UNSAFE_CLASSIFY_RESPONSE)

        result = guard.classify("violent content", gate="input")
        assert result.safe is False
        assert result.category == "S1"

    @respx.mock(base_url="http://localhost:8001")
    def test_fail_open_returns_safe(
        self, respx_mock: respx.MockRouter, guard_fail_open: Guard
    ) -> None:
        respx_mock.post("/v1/classify").mock(
            side_effect=httpx.ConnectError("Connection refused")
        )

        result = guard_fail_open.classify("test", gate="input")
        assert result.safe is True


# ---------------------------------------------------------------------------
# Guard.pii_scan()
# ---------------------------------------------------------------------------

class TestGuardPiiScan:
    @respx.mock(base_url="http://localhost:8001")
    def test_detects_pii(self, respx_mock: respx.MockRouter, guard: Guard) -> None:
        respx_mock.post("/v1/pii/scan").respond(json=PII_SCAN_RESPONSE)

        result = guard.pii_scan("john@example.com")
        assert result.has_pii is True
        assert len(result.entities) == 1
        assert result.entities[0].label == "email"

    @respx.mock(base_url="http://localhost:8001")
    def test_clean_text(self, respx_mock: respx.MockRouter, guard: Guard) -> None:
        respx_mock.post("/v1/pii/scan").respond(json=PII_SCAN_CLEAN_RESPONSE)

        result = guard.pii_scan("Hello world")
        assert result.has_pii is False
        assert result.entities == []

    @respx.mock(base_url="http://localhost:8001")
    def test_fail_open_returns_no_pii(
        self, respx_mock: respx.MockRouter, guard_fail_open: Guard
    ) -> None:
        respx_mock.post("/v1/pii/scan").mock(
            side_effect=httpx.ConnectError("Connection refused")
        )

        result = guard_fail_open.pii_scan("test")
        assert result.has_pii is False


# ---------------------------------------------------------------------------
# Guard.pii_mask()
# ---------------------------------------------------------------------------

class TestGuardPiiMask:
    @respx.mock(base_url="http://localhost:8001")
    def test_masks_pii(self, respx_mock: respx.MockRouter, guard: Guard) -> None:
        respx_mock.post("/v1/pii/mask").respond(json=PII_MASK_RESPONSE)

        masked = guard.pii_mask("My SSN is 123-45-6789")
        assert masked == "My SSN is [SSN]"

    @respx.mock(base_url="http://localhost:8001")
    def test_no_pii_returns_original(self, respx_mock: respx.MockRouter, guard: Guard) -> None:
        respx_mock.post("/v1/pii/mask").respond(
            json={"has_pii": False, "entities": [], "masked_text": "Hello world"}
        )

        masked = guard.pii_mask("Hello world")
        assert masked == "Hello world"


# ---------------------------------------------------------------------------
# Guard.wrap()
# ---------------------------------------------------------------------------

class TestGuardWrap:
    @respx.mock(base_url="http://localhost:8001")
    def test_wraps_function_screens_input_and_output(
        self, respx_mock: respx.MockRouter, guard: Guard
    ) -> None:
        # First call screens input, second screens output
        respx_mock.post("/v1/screen").respond(json=SAFE_SCREEN_RESPONSE)

        def my_tool(query: str) -> str:
            return "result from tool"

        safe_tool = guard.wrap(my_tool, gate="tool_input")
        result = safe_tool("safe query")
        # wrap() screens BOTH input and output via screen_or_raise, which
        # returns the (possibly masked) text from the screening result.
        # Each call hits the mocked /v1/screen endpoint, so:
        #   - call 1 (tool_input):  "safe query"       -> mock.text == "Hello world"
        #   - the wrapped tool runs: my_tool("Hello world") -> "result from tool"
        #   - call 2 (tool_output): "result from tool" -> mock.text == "Hello world"
        # Therefore the final result is the mock's canonical text, not None,
        # and BOTH input and output were screened.
        assert result == "Hello world"
        assert respx_mock.calls.call_count == 2

    @respx.mock(base_url="http://localhost:8001")
    def test_wrap_blocks_unsafe_input(
        self, respx_mock: respx.MockRouter, guard: Guard
    ) -> None:
        respx_mock.post("/v1/screen").respond(json=UNSAFE_SCREEN_RESPONSE)

        def my_tool(query: str) -> str:
            return "should not reach here"

        safe_tool = guard.wrap(my_tool, gate="tool_input")
        with pytest.raises(GuardExViolation):
            safe_tool("unsafe input")

    @respx.mock(base_url="http://localhost:8001")
    def test_wrap_no_output_screening(
        self, respx_mock: respx.MockRouter, guard: Guard
    ) -> None:
        respx_mock.post("/v1/screen").respond(json=SAFE_SCREEN_RESPONSE)

        def my_tool(query: str) -> str:
            return "tool output"

        safe_tool = guard.wrap(my_tool, gate="tool_input", screen_output=False)
        result = safe_tool("safe query")
        assert result == "tool output"
        # Only 1 call (input only, not output)
        assert respx_mock.calls.call_count == 1

    @respx.mock(base_url="http://localhost:8001")
    def test_wrap_preserves_function_name(
        self, respx_mock: respx.MockRouter, guard: Guard
    ) -> None:
        def search_web(query: str) -> str:
            """Search the web."""
            return "results"

        safe = guard.wrap(search_web, gate="tool_input")
        assert safe.__name__ == "search_web"
        assert "GuardEx-wrapped" in safe.__doc__


# ---------------------------------------------------------------------------
# Guard lifecycle
# ---------------------------------------------------------------------------

class TestGuardLifecycle:
    def test_context_manager(self, api_key: str, base_url: str) -> None:
        with Guard(api_key=api_key, base_url=base_url) as g:
            assert isinstance(g, Guard)

    def test_repr(self, guard: Guard) -> None:
        r = repr(guard)
        assert "Guard(" in r
        assert "base_url=" in r
        assert "fail_open=" in r


# ---------------------------------------------------------------------------
# API error handling
# ---------------------------------------------------------------------------

class TestGuardAPIErrors:
    @respx.mock(base_url="http://localhost:8001")
    def test_401_raises_api_error(self, respx_mock: respx.MockRouter, guard: Guard) -> None:
        respx_mock.post("/v1/screen").respond(
            status_code=401,
            json={"error": {"type": "auth_error", "message": "Invalid key", "code": "invalid_key"}},
        )

        with pytest.raises(GuardExAPIError) as exc_info:
            guard.screen("test", gate="input")
        assert exc_info.value.status_code == 401

    @respx.mock(base_url="http://localhost:8001")
    def test_422_raises_api_error(self, respx_mock: respx.MockRouter, guard: Guard) -> None:
        respx_mock.post("/v1/screen").respond(
            status_code=422,
            json={"error": {"type": "validation_error", "message": "Bad request", "code": "invalid"}},
        )

        with pytest.raises(GuardExAPIError) as exc_info:
            guard.screen("test", gate="input")
        assert exc_info.value.status_code == 422
