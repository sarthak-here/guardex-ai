"""Request/response format integration tests for GuardExClient.screen.

Captures actual httpx.Request objects via respx and asserts on:
  - JSON body shape (required keys, value types)
  - Custom headers (X-SDK-Version, Authorization)
  - PII entity parsing from typical server responses
"""

from __future__ import annotations

import json
from importlib.metadata import version as _pkg_version

import httpx
import pytest
import respx

from guardex.guard import Guard
from guardex.client import GuardExClient
from tests.helpers import SAFE_SCREEN_RESPONSE, PII_MASKED_SCREEN_RESPONSE


pytestmark = pytest.mark.integration


@respx.mock(base_url="http://localhost:8001")
def test_screen_request_body_has_expected_shape(
    respx_mock: respx.MockRouter, guard: Guard
) -> None:
    """The body POSTed to /v1/screen must include the core text/stage/pii_action keys."""
    route = respx_mock.post("/v1/screen").respond(json=SAFE_SCREEN_RESPONSE)

    guard.screen("Hello world", gate="input")

    assert route.called
    sent: httpx.Request = route.calls[-1].request
    body = json.loads(sent.content)

    # Required keys on every /v1/screen call
    for key in ("text", "stage", "pii_action"):
        assert key in body, f"missing key: {key}"

    assert body["text"] == "Hello world"
    assert body["stage"] == "input"
    assert isinstance(body["pii_action"], str)


@respx.mock(base_url="http://localhost:8001")
def test_screen_request_includes_sdk_version_header(
    respx_mock: respx.MockRouter, guard: Guard
) -> None:
    """Every outgoing request must carry X-SDK-Version pinned to the installed package."""
    route = respx_mock.post("/v1/screen").respond(json=SAFE_SCREEN_RESPONSE)

    guard.screen("hi", gate="input")

    sent_headers = route.calls[-1].request.headers
    # httpx lowercases header keys on the Headers object
    assert "x-sdk-version" in sent_headers
    assert sent_headers["x-sdk-version"] == _pkg_version("guardex-ai")


def test_screen_request_includes_auth_header_when_api_key_set():
    """When api_key is provided, Authorization: Bearer <key> must be sent."""
    base_url = "http://localhost:8001"
    with respx.mock(base_url=base_url) as router:
        route = router.post("/v1/screen").respond(json=SAFE_SCREEN_RESPONSE)

        client = GuardExClient(api_key="gx_test_auth_abc", base_url=base_url)
        client.screen("hi")

        sent_headers = route.calls[-1].request.headers
        assert sent_headers.get("authorization") == "Bearer gx_test_auth_abc"
        client.close()


def test_screen_request_omits_auth_header_when_no_api_key():
    """Self-hosted mode (no api_key, only base_url) must NOT send Authorization."""
    base_url = "http://localhost:8001"
    with respx.mock(base_url=base_url) as router:
        route = router.post("/v1/screen").respond(json=SAFE_SCREEN_RESPONSE)

        # No api_key — base_url alone is enough for self-hosted.
        client = GuardExClient(api_key=None, base_url=base_url)
        client.screen("hi")

        sent_headers = route.calls[-1].request.headers
        assert "authorization" not in sent_headers
        client.close()


@respx.mock(base_url="http://localhost:8001")
def test_screen_response_with_pii_parses_entities_correctly(
    respx_mock: respx.MockRouter, guard: Guard
) -> None:
    """A response with PII entities must parse into a typed PIIResult
    preserving label, score, and position."""
    respx_mock.post("/v1/screen").respond(json=PII_MASKED_SCREEN_RESPONSE)

    result = guard.screen("My SSN is 123-45-6789", gate="input")

    assert result.pii.has_pii is True
    assert len(result.pii.entities) == 1
    ent = result.pii.entities[0]
    assert ent.label == "ssn"
    assert ent.text == "123-45-6789"
    assert 0.0 <= ent.score <= 1.0
    # start/end positions preserved as integers
    assert isinstance(ent.start, int)
    assert isinstance(ent.end, int)
    assert ent.end > ent.start
    # masked_text applied to the result
    assert result.text == "My SSN is [SSN]"
    assert result.action == "mask"
