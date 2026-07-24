# SPDX-License-Identifier: Apache-2.0
"""Tests for the reference server - endpoint shapes, validation, and the
client-payload/server-schema contract."""
from __future__ import annotations

from typing import Any, Dict, List, Optional

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient  # noqa: E402

import guardex.server as server_module  # noqa: E402
from guardex.server import ScreenRequest, app  # noqa: E402


SAFE_RAW = {
    "classify": {"safe": True, "category": None, "categories": [], "confidence": 1.0},
    "pii": {"has_pii": False, "entities": [], "masked_text": None},
    "text": "hello",
    "_diagnostics": [],
}


class FakeRunner:
    """Stands in for LocalRunner so tests never load models."""

    def __init__(self) -> None:
        self.screen_kwargs: Optional[Dict[str, Any]] = None

    def screen(self, **kwargs: Any) -> tuple[Dict[str, Any], Optional[str]]:
        self.screen_kwargs = kwargs
        raw = dict(SAFE_RAW)
        raw["text"] = kwargs["text"]
        return raw, "req-123"

    def classify(self, text: str, stage: str = "input",
                 categories: Optional[List[str]] = None) -> Dict[str, Any]:
        return {"safe": True, "category": None, "categories": [], "confidence": 1.0}

    def pii_scan(self, text: str, entities: Optional[List[str]] = None,
                 threshold: float = 0.7) -> Dict[str, Any]:
        return {"has_pii": False, "entities": []}

    def pii_mask(self, text: str, entities: Optional[List[str]] = None,
                 threshold: float = 0.7) -> Dict[str, Any]:
        return {"has_pii": True, "entities": [], "masked_text": "[EMAIL]"}

    def check_grounding(self, response_text: str, sources: List[str],
                        mode: Optional[str] = None,
                        threshold: Optional[float] = None,
                        ) -> tuple[Dict[str, Any], Optional[str]]:
        return {"grounded": True, "faithfulness_score": 1.0, "details": []}, "req-456"


@pytest.fixture()
def fake_runner(monkeypatch) -> FakeRunner:
    runner = FakeRunner()
    monkeypatch.setattr(server_module, "_runner", runner)
    return runner


@pytest.fixture()
def client() -> TestClient:
    # No context manager: lifespan (model warmup) must not run in tests.
    return TestClient(app)


class TestEndpoints:
    def test_health(self, client):
        resp = client.get("/v1/health")
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "ok"
        assert body["mode"] == "local"

    def test_screen_shape_and_request_id_header(self, client, fake_runner):
        resp = client.post("/v1/screen", json={"text": "hello"})
        assert resp.status_code == 200
        assert resp.headers["X-GuardEx-Request-Id"] == "req-123"
        body = resp.json()
        assert body["classify"]["safe"] is True
        assert body["pii"]["has_pii"] is False
        assert body["text"] == "hello"

    def test_screen_forwards_custom_regex(self, client, fake_runner):
        resp = client.post("/v1/screen", json={
            "text": "employee EMP-123456",
            "pii_custom_regex": {"employee_id": r"EMP-\d{6}"},
        })
        assert resp.status_code == 200
        assert fake_runner.screen_kwargs is not None
        assert fake_runner.screen_kwargs["pii_custom_regex"] == {
            "employee_id": r"EMP-\d{6}"
        }

    def test_screen_batch(self, client, fake_runner):
        resp = client.post("/v1/screen/batch", json={
            "requests": [{"text": "one"}, {"text": "two"}],
        })
        assert resp.status_code == 200
        results = resp.json()["results"]
        assert len(results) == 2
        assert results[0]["text"] == "one"
        assert results[1]["text"] == "two"

    def test_classify(self, client, fake_runner):
        resp = client.post("/v1/classify", json={"text": "hello"})
        assert resp.status_code == 200
        assert resp.json()["safe"] is True

    def test_pii_scan(self, client, fake_runner):
        resp = client.post("/v1/pii/scan", json={"text": "hello"})
        assert resp.status_code == 200
        assert resp.json()["has_pii"] is False

    def test_pii_mask(self, client, fake_runner):
        resp = client.post("/v1/pii/mask", json={"text": "a@b.com"})
        assert resp.status_code == 200
        assert resp.json()["masked_text"] == "[EMAIL]"

    def test_grounding(self, client, fake_runner):
        resp = client.post("/v1/grounding", json={
            "response_text": "the sky is blue",
            "sources": ["the sky is blue"],
        })
        assert resp.status_code == 200
        assert resp.headers["X-GuardEx-Request-Id"] == "req-456"
        assert resp.json()["grounded"] is True


class TestCustomRegexValidation:
    def test_invalid_pattern_rejected(self, client, fake_runner):
        resp = client.post("/v1/screen", json={
            "text": "hi",
            "pii_custom_regex": {"bad": "("},
        })
        assert resp.status_code == 422
        assert fake_runner.screen_kwargs is None

    def test_too_many_patterns_rejected(self, client, fake_runner):
        patterns = {f"label_{i}": r"\d+" for i in range(33)}
        resp = client.post("/v1/screen", json={
            "text": "hi",
            "pii_custom_regex": patterns,
        })
        assert resp.status_code == 422

    def test_overlong_pattern_rejected(self, client, fake_runner):
        resp = client.post("/v1/screen", json={
            "text": "hi",
            "pii_custom_regex": {"long": "a" * 513},
        })
        assert resp.status_code == 422

    def test_valid_pattern_accepted(self, client, fake_runner):
        resp = client.post("/v1/screen", json={
            "text": "hi",
            "pii_custom_regex": {"mrn": r"MRN-\d{8}"},
        })
        assert resp.status_code == 200


class TestClientServerContract:
    """The payloads the SDK clients build must validate against the server schema."""

    def test_screen_payload_validates(self):
        from guardex._transport import build_screen_payload

        payload = build_screen_payload(
            text="hi", stage="input", pii_action="mask", pii_threshold=0.85,
            cascade_mode="safety", audit_log=True, categories=["S1"],
            pii_entities=["email"],
            pii_custom_regex={"employee_id": r"EMP-\d{6}"},
            scope_topics=["banking"], scope_utterances={"banking": ["balance"]},
            scope_examples=["what is my balance"], scope_width="narrow",
            scope_threshold=0.4, scope_alpha=0.3,
        )
        req = ScreenRequest.model_validate(payload)
        assert req.pii_custom_regex == {"employee_id": r"EMP-\d{6}"}
        assert req.scope_topics == ["banking"]

    def test_screen_batch_payload_validates(self):
        from guardex._transport import build_screen_batch_payload
        from guardex.server import ScreenBatchRequest

        payload = build_screen_batch_payload(
            texts=["one", "two"], stage="input", pii_action="mask",
            pii_threshold=0.7, cascade_mode="safety",
            categories=None, pii_entities=None,
        )
        batch = ScreenBatchRequest.model_validate(payload)
        assert len(batch.requests) == 2
