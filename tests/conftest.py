"""Shared fixtures for the GuardEx SDK test suite.

Provides mock API responses and pre-configured Guard instances
with respx-mocked HTTP transport.
"""

from __future__ import annotations

import pytest
import respx

from guardex.guard import Guard
from guardex.policy import GuardExPolicy

# Re-export constants so conftest still works as an import target
# for any test that uses `from conftest import ...` when run from tests/.
from tests.helpers import (  # noqa: F401 — re-exported for backward compat
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
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def base_url() -> str:
    return "http://localhost:8001"


@pytest.fixture()
def api_key() -> str:
    return "gx_test_abc123"


@pytest.fixture()
def policy(api_key: str, base_url: str) -> GuardExPolicy:
    """Default policy with PII masking enabled."""
    return GuardExPolicy(
        api_key=api_key,
        base_url=base_url,
        pii_enabled=True,
        pii_action="mask",
    )


@pytest.fixture()
def guard(api_key: str, base_url: str) -> Guard:
    """Guard instance configured for testing (default policy)."""
    g = Guard(api_key=api_key, base_url=base_url)
    yield g
    g.close()


@pytest.fixture()
def guard_fail_open(api_key: str, base_url: str) -> Guard:
    """Guard instance with fail_open=True."""
    g = Guard(api_key=api_key, base_url=base_url, fail_open=True)
    yield g
    g.close()


@pytest.fixture()
def mock_api(base_url: str):
    """Activate a respx mock router scoped to the test. Yields the router."""
    with respx.mock(base_url=base_url, assert_all_called=False) as router:
        yield router
