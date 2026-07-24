# SPDX-License-Identifier: Apache-2.0
"""Smoke tests for LocalRunner — verifies in-process ML pipeline."""
from __future__ import annotations

from unittest.mock import MagicMock, patch


def _make_runner(monkeypatch, fail_open: bool = False):
    """Create a LocalRunner with provider init state reset via monkeypatch.

    monkeypatch auto-reverts after the test, so global state is not leaked
    to other tests that import the runner module.
    """
    from guardex._engine.runner import LocalRunner
    monkeypatch.setattr(
        "guardex._engine.runner._providers_initialized", False, raising=False
    )
    return LocalRunner(fail_open=fail_open)


class TestLocalRunnerInterface:
    """LocalRunner exposes the same methods as GuardExClient."""

    def test_has_required_methods(self):
        from guardex._engine.runner import LocalRunner
        runner = LocalRunner()
        for method in ("screen", "classify", "pii_scan", "pii_mask",
                       "screen_batch", "check_grounding", "close"):
            assert callable(getattr(runner, method, None)), f"missing method: {method}"

    def test_screen_returns_tuple(self, monkeypatch):
        """screen() must return (dict, str|None) like GuardExClient."""
        from guardex._engine.runner import LocalRunner
        monkeypatch.setattr(
            "guardex._engine.runner._providers_initialized", False, raising=False
        )

        with patch("guardex._engine.runner._ensure_providers"):
            # Mock the ML pipeline internals
            with patch("guardex._engine.ml.input_validator.validate_input") as mock_val, \
                 patch("guardex._engine.ml.keyword_gate.check_keyword_gate") as mock_kw, \
                 patch("guardex._engine.ml.text_normalizer.normalize_for_classification",
                       return_value="hello"):

                mock_val.return_value = MagicMock(valid=True)
                mock_kw.return_value = MagicMock(matched=False)

                runner = LocalRunner()
                runner._classify_raw = MagicMock(return_value={
                    "safe": True, "category": None, "categories": [], "confidence": 1.0
                })
                runner._pii_raw = MagicMock(return_value={
                    "has_pii": False, "entities": [], "masked_text": None
                })

                result = runner.screen("hello world")

        assert isinstance(result, tuple), "screen() must return tuple"
        assert len(result) == 2, "screen() must return (dict, request_id)"
        raw, request_id = result
        assert "classify" in raw
        assert "pii" in raw
        assert "text" in raw

    def test_screen_batch_returns_list(self):
        """screen_batch() returns list of raw dicts, one per text."""
        from guardex._engine.runner import LocalRunner

        runner = LocalRunner()
        mock_raw = {"classify": {"safe": True, "category": None, "categories": [], "confidence": 1.0},
                    "pii": {"has_pii": False, "entities": []}, "text": "hi"}
        runner.screen = MagicMock(return_value=(mock_raw, "req-1"))

        results = runner.screen_batch(["text1", "text2"])

        assert isinstance(results, list)
        assert len(results) == 2
        # Each element must be a dict (not a tuple)
        for item in results:
            assert isinstance(item, dict)
            assert "classify" in item

    def test_screen_batch_empty(self):
        from guardex._engine.runner import LocalRunner
        runner = LocalRunner()
        assert runner.screen_batch([]) == []

    def test_fail_open_on_exception(self, monkeypatch):
        """fail_open=True causes screen() to return safe pass instead of raising."""
        from guardex._engine.runner import LocalRunner
        monkeypatch.setattr(
            "guardex._engine.runner._providers_initialized", False, raising=False
        )

        with patch("guardex._engine.runner._ensure_providers"), \
             patch("guardex._engine.ml.input_validator.validate_input",
                   side_effect=RuntimeError("test error")):

            runner = LocalRunner(fail_open=True)
            raw, req_id = runner.screen("boom")

        assert raw.get("_fail_open") is True
        assert req_id is None

    def test_keyword_gate_blocks(self, monkeypatch):
        """Keyword gate triggers early return with blocked classify result."""
        from guardex._engine.runner import LocalRunner
        monkeypatch.setattr(
            "guardex._engine.runner._providers_initialized", False, raising=False
        )

        val_mock = MagicMock(valid=True)
        kw_mock = MagicMock(matched=True, pattern="kill", category="S11")

        with patch("guardex._engine.runner._ensure_providers"), \
             patch("guardex._engine.ml.input_validator.validate_input",
                   return_value=val_mock), \
             patch("guardex._engine.ml.keyword_gate.check_keyword_gate",
                   return_value=kw_mock):

            runner = LocalRunner()
            raw, req_id = runner.screen("how to kill someone")

        assert raw["classify"]["safe"] is False
        assert raw["classify"]["category"] == "S11"
        assert req_id is not None


class TestPipelineConcurrency:
    def test_classify_and_pii_overlap(self, monkeypatch):
        """Classify and PII run concurrently, not sequentially.

        The fake classifier blocks until the fake PII detector has started;
        a sequential pipeline would never unblock it.
        """
        import threading
        from guardex._engine.runner import LocalRunner
        monkeypatch.setattr(
            "guardex._engine.runner._providers_initialized", False, raising=False
        )

        pii_started = threading.Event()

        def fake_classify(text, stage="input", categories=None, cascade_mode=None):
            assert pii_started.wait(timeout=5.0), \
                "PII never started while classify was pending - pipeline is sequential"
            return {"safe": True, "category": None, "categories": [], "confidence": 1.0}

        def fake_pii(text, **kwargs):
            pii_started.set()
            return {"has_pii": False, "entities": [], "masked_text": None}

        with patch("guardex._engine.runner._ensure_providers"), \
             patch("guardex._engine.ml.input_validator.validate_input",
                   return_value=MagicMock(valid=True)), \
             patch("guardex._engine.ml.keyword_gate.check_keyword_gate",
                   return_value=MagicMock(matched=False)), \
             patch("guardex._engine.ml.text_normalizer.normalize_for_classification",
                   return_value="hello"):

            runner = LocalRunner()
            runner._classify_raw = fake_classify
            runner._pii_raw = fake_pii

            raw, req_id = runner.screen("hello world")

        assert raw["classify"]["safe"] is True
        assert raw["pii"]["has_pii"] is False
        gates = {d["gate"]: d for d in raw["_diagnostics"]}
        assert gates["classify"]["ran"] is True
        assert gates["pii"]["ran"] is True
