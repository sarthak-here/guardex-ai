"""Tests for batch fallback, context on classify/pii_scan/stream, and min_confidence."""

import pytest
import respx
import httpx

from guardex.guard import Guard, _parse_screen_result
from guardex.policy import GuardExPolicy
from guardex._types import ScreenResult, ClassifyResult, PIIResult
from guardex.context import GuardExContext, DeploymentContext

from tests.helpers import (
    SAFE_SCREEN_RESPONSE,
    UNSAFE_SCREEN_RESPONSE,
    SAFE_CLASSIFY_RESPONSE,
    PII_SCAN_RESPONSE,
    PII_MASK_RESPONSE,
)


# ---------------------------------------------------------------------------
# Batch screening — Guard.screen_batch()
# ---------------------------------------------------------------------------

class TestGuardScreenBatch:
    @respx.mock(base_url="http://localhost:8001")
    def test_batch_returns_results_per_text(self, respx_mock, guard):
        respx_mock.post("/v1/screen/batch").respond(json={
            "results": [SAFE_SCREEN_RESPONSE, UNSAFE_SCREEN_RESPONSE],
        })

        results = guard.screen_batch(["hello", "bomb"], gate="input")
        assert len(results) == 2
        assert results[0].safe is True
        assert results[1].blocked is True

    @respx.mock(base_url="http://localhost:8001")
    def test_batch_empty_returns_empty(self, respx_mock, guard):
        results = guard.screen_batch([], gate="input")
        assert results == []

    @respx.mock(base_url="http://localhost:8001")
    def test_batch_fallback_on_404(self, respx_mock, guard):
        """If batch endpoint returns 404, SDK falls back to sequential."""
        # Batch returns 404
        respx_mock.post("/v1/screen/batch").respond(status_code=404, json={
            "error": {"type": "not_found", "message": "Not Found", "code": "not_found"}
        })
        # Individual screen calls succeed
        respx_mock.post("/v1/screen").respond(json=SAFE_SCREEN_RESPONSE)

        results = guard.screen_batch(["text1", "text2"], gate="input")
        assert len(results) == 2
        assert all(r.safe for r in results)


# ---------------------------------------------------------------------------
# Context on classify(), pii_scan(), pii_mask()
# ---------------------------------------------------------------------------

class TestContextOnMethods:
    @respx.mock(base_url="http://localhost:8001")
    def test_classify_with_context(self, respx_mock, guard):
        route = respx_mock.post("/v1/classify").respond(json=SAFE_CLASSIFY_RESPONSE)

        ctx = GuardExContext(deployment=DeploymentContext.PRODUCTION)
        result = guard.classify("hello", gate="input", context=ctx)
        assert result.safe is True

    @respx.mock(base_url="http://localhost:8001")
    def test_pii_scan_with_context(self, respx_mock, guard):
        respx_mock.post("/v1/pii/scan").respond(json=PII_SCAN_RESPONSE)

        ctx = GuardExContext(deployment=DeploymentContext.PRODUCTION)
        result = guard.pii_scan("john@example.com", context=ctx)
        assert result.has_pii is True

    @respx.mock(base_url="http://localhost:8001")
    def test_pii_mask_with_context(self, respx_mock, guard):
        respx_mock.post("/v1/pii/mask").respond(json=PII_MASK_RESPONSE)

        ctx = GuardExContext(deployment=DeploymentContext.PRODUCTION)
        result = guard.pii_mask("My SSN is 123-45-6789", context=ctx)
        assert result == "My SSN is [SSN]"


# min_confidence threshold tests

class TestMinConfidence:
    def test_low_confidence_overridden_to_safe(self):
        """Unsafe result with confidence below threshold is overridden to safe."""
        raw = {
            "pii": {"has_pii": False, "entities": []},
            "classify": {
                "safe": False,
                "category": "S9",
                "categories": ["S9"],
                "confidence": 0.3,
            },
            "text": "borderline text",
        }
        result = _parse_screen_result(raw, "input", "borderline text",
                                       min_confidence=0.7)
        # Should be overridden to safe because 0.3 < 0.7
        assert result.safe is True
        assert result.action == "pass"
        assert result.classify.safe is True
        assert result.classify.category == "S9"  # category preserved for info
        assert "overridden" in result.classify.description

    def test_high_confidence_not_overridden(self):
        """Unsafe result with confidence above threshold is NOT overridden."""
        raw = {
            "pii": {"has_pii": False, "entities": []},
            "classify": {
                "safe": False,
                "category": "S9",
                "categories": ["S9"],
                "confidence": 0.95,
            },
            "text": "definitely unsafe",
        }
        result = _parse_screen_result(raw, "input", "definitely unsafe",
                                       min_confidence=0.7)
        assert result.blocked is True
        assert result.classify.safe is False

    def test_zero_threshold_never_overrides(self):
        """Default threshold 0.0 means no override ever happens."""
        raw = {
            "pii": {"has_pii": False, "entities": []},
            "classify": {
                "safe": False,
                "category": "S1",
                "categories": ["S1"],
                "confidence": 0.01,
            },
            "text": "text",
        }
        result = _parse_screen_result(raw, "input", "text", min_confidence=0.0)
        assert result.blocked is True

    def test_safe_result_not_affected(self):
        """Safe results are never affected by min_confidence."""
        raw = {
            "pii": {"has_pii": False, "entities": []},
            "classify": {
                "safe": True,
                "category": None,
                "categories": [],
                "confidence": 0.1,
            },
            "text": "safe text",
        }
        result = _parse_screen_result(raw, "input", "safe text",
                                       min_confidence=0.9)
        assert result.safe is True

    @respx.mock(base_url="http://localhost:8001")
    def test_guard_uses_policy_min_confidence(self, respx_mock):
        """Guard.screen() passes policy's min_confidence to parser."""
        respx_mock.post("/v1/screen").respond(json={
            "pii": {"has_pii": False, "entities": []},
            "classify": {
                "safe": False,
                "category": "S9",
                "categories": ["S9"],
                "confidence": 0.4,
            },
            "text": "borderline",
        })

        policy = GuardExPolicy(
            api_key="gx_test_123",
            base_url="http://localhost:8001",
            classify_min_confidence=0.7,
        )
        g = Guard(policy=policy, injection_check=False)
        try:
            result = g.screen("borderline", gate="input")
            # Should be overridden to safe
            assert result.safe is True
            assert result.action == "pass"
        finally:
            g.close()


# ---------------------------------------------------------------------------
# Policy field exists
# ---------------------------------------------------------------------------

class TestPolicyMinConfidenceField:
    def test_default_is_zero(self):
        p = GuardExPolicy()
        assert p.classify_min_confidence == 0.0

    def test_custom_value(self):
        p = GuardExPolicy(classify_min_confidence=0.6)
        assert p.classify_min_confidence == 0.6
