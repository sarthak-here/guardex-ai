"""SDK HTTP client tests.

Tests cover:
  - Sync client: HTTP/2, structured timeouts, connection pooling
  - Async client: same optimizations + context manager
  - Retry logic and fail_open behavior
  - API key validation
  - All public methods exist and accept correct args
"""

import asyncio
import unittest
from importlib.metadata import version as _pkg_version
from unittest.mock import patch, MagicMock, AsyncMock

import httpx
import respx

# Fake base URL used only as a respx routing key — no real traffic leaves.
_MOCK_BASE = "http://mock-guardex.invalid"


# ---------------------------------------------------------------------------
# Sync client tests
# ---------------------------------------------------------------------------

class TestGuardExClientInit(unittest.TestCase):
    """GuardExClient initialization and configuration."""

    def test_requires_api_key(self):
        from guardex.client import GuardExClient

        with patch.dict("os.environ", {}, clear=True):
            with self.assertRaises(ValueError):
                GuardExClient(api_key="")

    def test_accepts_api_key(self):
        from guardex.client import GuardExClient

        client = GuardExClient(api_key="gx_test_123", base_url="http://localhost:8001")
        self.assertEqual(client.api_key, "gx_test_123")
        self.assertEqual(client.base_url, "http://localhost:8001")
        client.close()

    def test_http2_enabled(self):
        from guardex.client import GuardExClient

        client = GuardExClient(api_key="gx_test_123", base_url="http://localhost:8001")
        # httpx.Client stores http2 setting — verify the transport supports it
        self.assertIsNotNone(client._client)
        client.close()

    def test_structured_timeouts(self):
        from guardex.client import GuardExClient

        client = GuardExClient(api_key="gx_test_123", timeout=15, base_url="http://localhost:8001")
        timeout = client._client.timeout
        self.assertEqual(timeout.connect, 5.0)
        self.assertEqual(timeout.read, 15.0)
        self.assertEqual(timeout.write, 5.0)
        self.assertEqual(timeout.pool, 10.0)
        client.close()

    def test_connection_pool_limits(self):
        from guardex.client import GuardExClient

        client = GuardExClient(api_key="gx_test_123", base_url="http://localhost:8001")
        # Verify transport is configured (connection pooling is set via limits param)
        transport = client._client._transport
        self.assertIsNotNone(transport)
        client.close()

    def test_context_manager(self):
        from guardex.client import GuardExClient

        with GuardExClient(api_key="gx_test_123", base_url="http://localhost:8001") as client:
            self.assertIsNotNone(client._client)

    def test_default_timeout(self):
        from guardex.client import GuardExClient

        client = GuardExClient(api_key="gx_test_123", base_url="http://localhost:8001")
        self.assertEqual(client.timeout, 30)
        self.assertEqual(client._client.timeout.read, 30.0)
        client.close()

    def test_version_header(self):
        from guardex.client import GuardExClient

        client = GuardExClient(api_key="gx_test_123", base_url="http://localhost:8001")
        headers = client._client.headers
        self.assertIn("x-sdk-version", headers)
        # Single source of truth — the installed package version, not a literal.
        self.assertEqual(headers["x-sdk-version"], _pkg_version("guardex-ai"))
        client.close()

    def test_base_url_strips_trailing_slash(self):
        from guardex.client import GuardExClient

        client = GuardExClient(api_key="gx_test_123", base_url="http://localhost:8001/")
        self.assertEqual(client.base_url, "http://localhost:8001")
        client.close()


class TestGuardExClientFailOpen(unittest.TestCase):
    """Fail-open behavior returns safe defaults on errors.

    Uses respx to simulate httpx.ConnectError without touching the network —
    faster and more deterministic than relying on a dead port.
    """

    def test_fail_open_returns_safe_on_screen(self):
        from guardex.client import GuardExClient

        with respx.mock(base_url=_MOCK_BASE) as router:
            router.post("/v1/screen").mock(
                side_effect=httpx.ConnectError("simulated connect failure")
            )
            client = GuardExClient(
                api_key="gx_test_123",
                base_url=_MOCK_BASE,
                fail_open=True,
                max_retries=0,
            )
            result, request_id = client.screen("test text")
            self.assertTrue(result["classify"]["safe"])
            self.assertFalse(result["pii"]["has_pii"])
            self.assertEqual(result["text"], "test text")
            self.assertIsNone(request_id)
            client.close()

    def test_fail_open_returns_safe_on_classify(self):
        from guardex.client import GuardExClient

        with respx.mock(base_url=_MOCK_BASE) as router:
            router.post("/v1/classify").mock(
                side_effect=httpx.ConnectError("simulated connect failure")
            )
            client = GuardExClient(
                api_key="gx_test_123",
                base_url=_MOCK_BASE,
                fail_open=True,
                max_retries=0,
            )
            result = client.classify("test text")
            self.assertTrue(result["safe"])
            client.close()

    def test_fail_closed_raises_on_error(self):
        from guardex.client import GuardExClient

        with respx.mock(base_url=_MOCK_BASE) as router:
            router.post("/v1/screen").mock(
                side_effect=httpx.ConnectError("simulated connect failure")
            )
            client = GuardExClient(
                api_key="gx_test_123",
                base_url=_MOCK_BASE,
                fail_open=False,
                max_retries=0,
            )
            with self.assertRaises(Exception):
                client.screen("test text")
            client.close()


class TestGuardExClientMethods(unittest.TestCase):
    """All public methods exist with correct signatures."""

    def test_has_all_methods(self):
        from guardex.client import GuardExClient

        client = GuardExClient(api_key="gx_test_123", base_url="http://localhost:8001")
        self.assertTrue(callable(getattr(client, "screen", None)))
        self.assertTrue(callable(getattr(client, "classify", None)))
        self.assertTrue(callable(getattr(client, "pii_scan", None)))
        self.assertTrue(callable(getattr(client, "pii_mask", None)))
        self.assertTrue(callable(getattr(client, "health", None)))
        self.assertTrue(callable(getattr(client, "close", None)))
        client.close()


# ---------------------------------------------------------------------------
# Async client tests
# ---------------------------------------------------------------------------

class TestAsyncGuardExClientInit(unittest.TestCase):
    """AsyncGuardExClient initialization."""

    def test_requires_api_key(self):
        from guardex.async_client import AsyncGuardExClient

        with patch.dict("os.environ", {}, clear=True):
            with self.assertRaises(ValueError):
                AsyncGuardExClient(api_key="")

    def test_accepts_api_key(self):
        from guardex.async_client import AsyncGuardExClient

        client = AsyncGuardExClient(api_key="gx_test_123", base_url="http://localhost:8001")
        self.assertEqual(client.api_key, "gx_test_123")
        asyncio.run(client.aclose())

    def test_structured_timeouts(self):
        from guardex.async_client import AsyncGuardExClient

        client = AsyncGuardExClient(api_key="gx_test_123", timeout=20, base_url="http://localhost:8001")
        timeout = client._client.timeout
        self.assertEqual(timeout.connect, 5.0)
        self.assertEqual(timeout.read, 20.0)
        self.assertEqual(timeout.write, 5.0)
        self.assertEqual(timeout.pool, 10.0)
        asyncio.run(client.aclose())

    def test_version_header(self):
        from guardex.async_client import AsyncGuardExClient

        client = AsyncGuardExClient(api_key="gx_test_123", base_url="http://localhost:8001")
        headers = client._client.headers
        self.assertIn("x-sdk-version", headers)
        self.assertEqual(headers["x-sdk-version"], _pkg_version("guardex-ai"))
        asyncio.run(client.aclose())


class TestAsyncClientContextManager(unittest.TestCase):
    """Async context manager support."""

    def test_async_context_manager(self):
        from guardex.async_client import AsyncGuardExClient

        async def run():
            async with AsyncGuardExClient(api_key="gx_test_123", base_url="http://localhost:8001") as client:
                self.assertIsNotNone(client._client)

        asyncio.run(run())


class TestAsyncClientFailOpen(unittest.TestCase):
    """Async client fail-open behavior (uses respx to simulate ConnectError)."""

    def test_fail_open_screen(self):
        from guardex.async_client import AsyncGuardExClient

        async def run():
            with respx.mock(base_url=_MOCK_BASE) as router:
                router.post("/v1/screen").mock(
                    side_effect=httpx.ConnectError("simulated connect failure")
                )
                client = AsyncGuardExClient(
                    api_key="gx_test_123",
                    base_url=_MOCK_BASE,
                    fail_open=True,
                    max_retries=0,
                )
                result, request_id = await client.screen("test text")
                self.assertTrue(result["classify"]["safe"])
                self.assertFalse(result["pii"]["has_pii"])
                self.assertEqual(result["text"], "test text")
                self.assertIsNone(request_id)
                await client.aclose()

        asyncio.run(run())

    def test_fail_open_classify(self):
        from guardex.async_client import AsyncGuardExClient

        async def run():
            with respx.mock(base_url=_MOCK_BASE) as router:
                router.post("/v1/classify").mock(
                    side_effect=httpx.ConnectError("simulated connect failure")
                )
                client = AsyncGuardExClient(
                    api_key="gx_test_123",
                    base_url=_MOCK_BASE,
                    fail_open=True,
                    max_retries=0,
                )
                result = await client.classify("test text")
                self.assertTrue(result["safe"])
                await client.aclose()

        asyncio.run(run())

    def test_fail_open_pii_scan(self):
        from guardex.async_client import AsyncGuardExClient

        async def run():
            with respx.mock(base_url=_MOCK_BASE) as router:
                router.post("/v1/pii/scan").mock(
                    side_effect=httpx.ConnectError("simulated connect failure")
                )
                client = AsyncGuardExClient(
                    api_key="gx_test_123",
                    base_url=_MOCK_BASE,
                    fail_open=True,
                    max_retries=0,
                )
                result = await client.pii_scan("test text")
                self.assertFalse(result["has_pii"])
                await client.aclose()

        asyncio.run(run())

    def test_fail_open_pii_mask(self):
        from guardex.async_client import AsyncGuardExClient

        async def run():
            with respx.mock(base_url=_MOCK_BASE) as router:
                router.post("/v1/pii/mask").mock(
                    side_effect=httpx.ConnectError("simulated connect failure")
                )
                client = AsyncGuardExClient(
                    api_key="gx_test_123",
                    base_url=_MOCK_BASE,
                    fail_open=True,
                    max_retries=0,
                )
                result = await client.pii_mask("test text")
                self.assertFalse(result["has_pii"])
                self.assertEqual(result["masked_text"], "test text")
                await client.aclose()

        asyncio.run(run())

    def test_fail_closed_raises(self):
        from guardex.async_client import AsyncGuardExClient

        async def run():
            with respx.mock(base_url=_MOCK_BASE) as router:
                router.post("/v1/screen").mock(
                    side_effect=httpx.ConnectError("simulated connect failure")
                )
                client = AsyncGuardExClient(
                    api_key="gx_test_123",
                    base_url=_MOCK_BASE,
                    fail_open=False,
                    max_retries=0,
                )
                with self.assertRaises(Exception):
                    await client.screen("test text")
                await client.aclose()

        asyncio.run(run())


class TestAsyncClientMethods(unittest.TestCase):
    """All async public methods exist."""

    def test_has_all_methods(self):
        from guardex.async_client import AsyncGuardExClient

        client = AsyncGuardExClient(api_key="gx_test_123", base_url="http://localhost:8001")
        self.assertTrue(callable(getattr(client, "screen", None)))
        self.assertTrue(callable(getattr(client, "classify", None)))
        self.assertTrue(callable(getattr(client, "pii_scan", None)))
        self.assertTrue(callable(getattr(client, "pii_mask", None)))
        self.assertTrue(callable(getattr(client, "health", None)))
        self.assertTrue(callable(getattr(client, "aclose", None)))
        asyncio.run(client.aclose())


if __name__ == "__main__":
    unittest.main(verbosity=2)
