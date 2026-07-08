"""Retry logic coverage for GuardExClient and AsyncGuardExClient.

Behavior under test (from guardex/client.py._request):
  - 429 with Retry-After header: sleeps `min(Retry-After, 30)`s and retries
    up to max_retries times.
  - Network exceptions (ConnectError, ReadTimeout, etc.): retry with
    exponential backoff (2**attempt * 0.5 + jitter).
  - 500 (no Retry-After): raises GuardExAPIError immediately — no retry.
  - 401/403/422: raises GuardExAPIError immediately — never retried.
  - After max_retries exhausted: either raises (fail_open=False) or returns
    a _fail_open payload (fail_open=True).

All tests patch time.sleep so no real waiting occurs.
"""

from __future__ import annotations

import asyncio
from unittest.mock import patch

import httpx
import pytest
import respx

from guardex.client import GuardExClient
from guardex.async_client import AsyncGuardExClient
from guardex.exceptions import GuardExAPIError

_BASE = "http://mock-guardex-retry.invalid"


@pytest.mark.slow
def test_client_retries_on_429_with_retry_after_header():
    """429 with Retry-After: sleep and retry; succeed on the second call."""
    success = {
        "pii": {"has_pii": False, "entities": []},
        "classify": {"safe": True, "category": None, "categories": []},
        "text": "ok",
    }

    with respx.mock(base_url=_BASE) as router:
        route = router.post("/v1/screen").mock(
            side_effect=[
                httpx.Response(429, headers={"Retry-After": "0"}, json={}),
                httpx.Response(200, json=success),
            ]
        )

        client = GuardExClient(api_key="gx_test", base_url=_BASE, max_retries=2)
        # Patch the module-level time.sleep in client.py to zero out waits.
        with patch("guardex.client.time.sleep") as sleep_mock:
            body, _req_id = client._request("POST", "/v1/screen", json={"text": "ok"})

        assert body == success
        assert route.call_count == 2  # retried once
        sleep_mock.assert_called()  # sleep triggered on Retry-After
        client.close()


@pytest.mark.slow
def test_client_retries_on_network_error_with_exponential_backoff():
    """Network exceptions (ConnectError) trigger exponential-backoff retry."""
    success = {
        "pii": {"has_pii": False, "entities": []},
        "classify": {"safe": True, "category": None, "categories": []},
        "text": "ok",
    }

    with respx.mock(base_url=_BASE) as router:
        route = router.post("/v1/screen").mock(
            side_effect=[
                httpx.ConnectError("first attempt fails"),
                httpx.ConnectError("second attempt fails"),
                httpx.Response(200, json=success),
            ]
        )

        client = GuardExClient(api_key="gx_test", base_url=_BASE, max_retries=2)
        with patch("guardex.client.time.sleep") as sleep_mock:
            body, _req_id = client._request("POST", "/v1/screen", json={"text": "x"})

        assert body == success
        assert route.call_count == 3  # initial + 2 retries
        # Two sleeps (one per retry) with exponential-backoff values.
        assert sleep_mock.call_count == 2
        first_backoff = sleep_mock.call_args_list[0].args[0]
        second_backoff = sleep_mock.call_args_list[1].args[0]
        # 2^0 * 0.5 = 0.5 base; 2^1 * 0.5 = 1.0 base; + up to 0.25 jitter.
        assert 0.5 <= first_backoff <= 0.75
        assert 1.0 <= second_backoff <= 1.25
        client.close()


def test_client_retries_500_without_retry_after_using_exp_backoff():
    """500 with no Retry-After must retry with exponential backoff and
    then raise GuardExAPIError once retries are exhausted.

    Asymmetric retry (5xx-with-header retries, 5xx-without-header
    doesn't) was a real bug — the SDK now treats 5xx uniformly and falls
    back to exponential backoff when Retry-After is absent.
    """
    with respx.mock(base_url=_BASE) as router:
        route = router.post("/v1/screen").mock(
            return_value=httpx.Response(500, json={})
        )

        client = GuardExClient(
            api_key="gx_test", base_url=_BASE, max_retries=3, fail_open=False
        )
        with patch("guardex.client.time.sleep"):
            with pytest.raises(GuardExAPIError) as exc_info:
                client._request("POST", "/v1/screen", json={"text": "x"})

        assert exc_info.value.status_code == 500
        # max_retries=3 => 1 initial + 3 retries = 4 total attempts.
        assert route.call_count == 4
        client.close()


def test_client_fails_after_max_retries_exceeded():
    """After max_retries network failures, fail_open=False raises the last exception."""
    with respx.mock(base_url=_BASE) as router:
        route = router.post("/v1/screen").mock(
            side_effect=httpx.ConnectError("persistent network failure")
        )

        client = GuardExClient(
            api_key="gx_test", base_url=_BASE, max_retries=2, fail_open=False
        )
        with patch("guardex.client.time.sleep"):
            with pytest.raises(httpx.ConnectError):
                client._request("POST", "/v1/screen", json={"text": "x"})

        # Initial + 2 retries = 3 total attempts.
        assert route.call_count == 3
        client.close()


def test_async_client_retries_match_sync_behavior():
    """The async client must mirror sync retry semantics for network errors."""
    success = {
        "pii": {"has_pii": False, "entities": []},
        "classify": {"safe": True, "category": None, "categories": []},
        "text": "ok",
    }

    async def run():
        with respx.mock(base_url=_BASE) as router:
            route = router.post("/v1/screen").mock(
                side_effect=[
                    httpx.ConnectError("fail 1"),
                    httpx.Response(200, json=success),
                ]
            )

            client = AsyncGuardExClient(api_key="gx_test", base_url=_BASE, max_retries=2)

            # Patch asyncio.sleep inside async_client module to avoid real waits.
            async def _no_sleep(_seconds):
                return None

            with patch("guardex.async_client.asyncio.sleep", _no_sleep):
                body, _req_id = await client._request("POST", "/v1/screen", json={"text": "x"})

            assert body == success
            assert route.call_count == 2
            await client.aclose()

    asyncio.run(run())
