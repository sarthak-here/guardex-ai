# SPDX-License-Identifier: Apache-2.0
"""Regression tests for OSS-launch hardening fixes.

Each test pins a specific defect found before launch so it cannot silently
return: cascade_mode propagation, PII context self-corroboration, fail-open
observability, and Ollama-escalation fail-open behavior.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest


class TestCascadeModePropagation:
    """policy.cascade_mode must reach the classifier provider in local mode."""

    def test_cascade_mode_reaches_provider(self, monkeypatch):
        from guardex._engine.runner import LocalRunner
        monkeypatch.setattr(
            "guardex._engine.runner._providers_initialized", False, raising=False
        )
        recorded: dict = {}

        class _RecordingProvider:
            async def classify(self, text, stage="input", categories=None, cascade_mode=None):
                recorded["cascade_mode"] = cascade_mode
                return {"safe": True, "category": None, "categories": [], "confidence": 1.0}

        with patch("guardex._engine.runner._ensure_providers"), \
             patch("guardex._engine.providers.registry.get_classifier_provider",
                   return_value=_RecordingProvider()), \
             patch("guardex._engine.ml.input_validator.validate_input",
                   return_value=MagicMock(valid=True)), \
             patch("guardex._engine.ml.keyword_gate.check_keyword_gate",
                   return_value=MagicMock(matched=False)), \
             patch("guardex._engine.ml.text_normalizer.normalize_for_classification",
                   return_value="hi"):
            runner = LocalRunner()
            runner._pii_raw = MagicMock(
                return_value={"has_pii": False, "entities": [], "masked_text": None}
            )
            runner.screen("hello", cascade_mode="speed")

        assert recorded["cascade_mode"] == "speed"


class TestPiiContextEnhance:
    """A phrase must not boost its own PII score via words inside its own span."""

    def test_no_self_corroboration(self):
        from guardex._engine.services.pii_regex import context_enhance
        text = "What are your rates on a High-Yield Savings Account?"
        span = "High-Yield Savings Account"
        start = text.index(span)
        ent = {"label": "bank_account", "text": span,
               "start": start, "end": start + len(span), "score": 0.7}
        out = context_enhance(text, [ent])
        assert out[0]["context_boost"] is False
        assert out[0]["score"] == 0.7

    def test_real_account_number_still_boosts(self):
        from guardex._engine.services.pii_regex import context_enhance
        text = "my bank account number is 000123456789 thanks"
        num = "000123456789"
        start = text.index(num)
        ent = {"label": "bank_account", "text": num,
               "start": start, "end": start + len(num), "score": 0.7}
        out = context_enhance(text, [ent])
        assert out[0]["context_boost"] is True
        assert out[0]["score"] > 0.7


class TestFailOpenObservability:
    """Fail-open results must be marked degraded so they aren't read as a real pass."""

    def test_fail_open_marks_degraded(self):
        from guardex.guard import _parse_screen_result
        res = _parse_screen_result(
            {"_fail_open": True}, gate="input", original_text="hi", request_id="r1"
        )
        assert res.degraded is True
        assert res.action == "pass"

    def test_normal_result_not_degraded(self):
        from guardex.guard import _parse_screen_result
        raw = {
            "classify": {"safe": True, "category": None, "categories": [], "confidence": 1.0},
            "pii": {"has_pii": False, "entities": []},
            "text": "hi",
        }
        res = _parse_screen_result(raw, gate="input", original_text="hi")
        assert res.degraded is False


class TestCascadeEscalateFailOpen:
    """Escalation call failure must honor fail_open, not unconditionally block."""

    def _provider(self, fail_open: bool):
        from guardex._engine.providers.cascade_provider import CascadeClassifierProvider

        async def _raise(*args, **kwargs):
            raise RuntimeError("ollama unreachable")

        slow = MagicMock()
        slow.classify = _raise
        return CascadeClassifierProvider(
            fast_engine=MagicMock(), slow_provider=slow, fail_open=fail_open
        )

    @pytest.mark.asyncio
    async def test_fail_closed_by_default(self):
        res = await self._provider(fail_open=False)._escalate("t", "input", None)
        assert res["safe"] is False
        assert res["_cascade_path"] == "escalation_failed"

    @pytest.mark.asyncio
    async def test_fail_open_when_enabled(self):
        res = await self._provider(fail_open=True)._escalate("t", "input", None)
        assert res["safe"] is True


class TestOllamaProbeModelAware:
    """The probe must require the configured model, not just a live server.

    A reachable Ollama without llama-guard3 made every escalation fail
    closed and block benign text in default local mode.
    """

    def _resp(self, models):
        import httpx
        return httpx.Response(
            200,
            json={"models": [{"name": n} for n in models]},
            headers={"content-type": "application/json"},
        )

    def test_server_up_model_missing_fails(self):
        from guardex.guard import _probe_ollama
        with patch("httpx.get", return_value=self._resp(["qwen3:latest"])):
            assert _probe_ollama("http://x", "llama-guard3:1b") is False

    def test_model_present_passes(self):
        from guardex.guard import _probe_ollama
        with patch("httpx.get", return_value=self._resp(["llama-guard3:1b"])):
            assert _probe_ollama("http://x", "llama-guard3:1b") is True

    def test_base_name_match(self):
        from guardex.guard import _probe_ollama
        with patch("httpx.get", return_value=self._resp(["llama-guard3:8b"])):
            assert _probe_ollama("http://x", "llama-guard3") is True


class TestCascadeEscalationFallback:
    """Escalation failure must degrade to the fast verdict, not block."""

    def _provider(self):
        from guardex._engine.providers.cascade_provider import CascadeClassifierProvider

        async def _raise(*args, **kwargs):
            raise RuntimeError("ollama cold")

        slow = MagicMock()
        slow.classify = _raise
        return CascadeClassifierProvider(
            fast_engine=MagicMock(), slow_provider=slow, fail_open=False
        )

    @pytest.mark.asyncio
    async def test_falls_back_to_fast_verdict(self):
        p = self._provider()
        fast = {"safe": True, "category": None, "categories": []}
        res = await p._escalate("t", "input", None, fast_result=fast)
        assert res["safe"] is True
        assert res["_cascade_path"] == "escalation_failed_fast_fallback"

    @pytest.mark.asyncio
    async def test_unsafe_fast_verdict_survives_fallback(self):
        p = self._provider()
        fast = {"safe": False, "category": "S1", "categories": ["S1"]}
        res = await p._escalate("t", "input", None, fast_result=fast)
        assert res["safe"] is False
        assert res["category"] == "S1"

    @pytest.mark.asyncio
    async def test_breaker_skips_after_threshold(self):
        p = self._provider()
        fast = {"safe": True, "category": None, "categories": []}
        for _ in range(p._BREAKER_THRESHOLD):
            await p._escalate("t", "input", None, fast_result=fast)
        res = await p._escalate("t", "input", None, fast_result=fast)
        assert res["_cascade_path"] == "escalation_skipped_breaker"


class TestFromYamlFieldDrop:
    """from_yaml must apply default_factory fields, not drop them as unknown."""

    def test_default_factory_fields_applied(self, tmp_path):
        pytest.importorskip("yaml")
        from guardex.policy import GuardExPolicy

        p = tmp_path / "policy.yaml"
        p.write_text(
            "api_key: gx_test\n"
            "base_url: http://example.com:9999\n"
            "blocked_categories: [S1, S2]\n"
            "pii_entities: [email, ssn]\n"
            "pii_threshold: 0.5\n",
            encoding="utf-8",
        )
        pol = GuardExPolicy.from_yaml(str(p))
        assert pol.api_key == "gx_test"
        assert pol.base_url == "http://example.com:9999"
        assert pol.blocked_categories == ["S1", "S2"]
        assert pol.pii_entities == ["email", "ssn"]
        assert pol.pii_threshold == 0.5

    def test_safety_routes_applied(self, tmp_path):
        pytest.importorskip("yaml")
        pytest.importorskip("numpy")
        from guardex.policy import GuardExPolicy

        p = tmp_path / "policy.yaml"
        p.write_text(
            "safety_routes:\n"
            "  - name: competitors\n"
            "    utterances: ['tell me about acme corp']\n",
            encoding="utf-8",
        )
        pol = GuardExPolicy.from_yaml(str(p))
        assert len(pol.safety_routes) == 1
        assert pol.safety_routes[0].name == "competitors"


class TestVaultDigitLabels:
    """Vault tokens for labels containing digits (ipv6_address) must restore."""

    def test_ipv6_label_round_trip(self):
        from guardex._types import PIIEntity, PIIResult
        from guardex.pii_vault import PIIVault

        text = "ping 2001:db8::1 now"
        ent = PIIEntity(
            text="2001:db8::1", label="ipv6_address", score=0.99, start=5, end=16
        )
        vault = PIIVault()
        vaulted, vault = vault.vault_text(text, PIIResult(has_pii=True, entities=[ent]))
        assert "{{pii:ipv6_address:" in vaulted
        assert vault.restore(vaulted) == text


class TestClientErrorSemantics:
    """fail_open covers exhausted 5xx; terminal 4xx raise with no retry."""

    def test_persistent_500_fails_open(self):
        import httpx
        import respx
        from guardex import GuardExClient

        with respx.mock(base_url="http://test") as mock:
            mock.post("/v1/screen").mock(return_value=httpx.Response(500))
            client = GuardExClient(base_url="http://test", fail_open=True, max_retries=0)
            body, _ = client.screen("hi")
            assert body["_fail_open"] is True
            assert body["text"] == "hi"

    def test_persistent_500_raises_fail_closed(self):
        import httpx
        import respx
        from guardex import GuardExClient
        from guardex.exceptions import GuardExAPIError

        with respx.mock(base_url="http://test") as mock:
            mock.post("/v1/classify").mock(return_value=httpx.Response(500))
            client = GuardExClient(base_url="http://test", fail_open=False, max_retries=0)
            with pytest.raises(GuardExAPIError) as exc_info:
                client.classify("hi")
            assert exc_info.value.status_code == 500

    def test_404_raises_immediately_even_with_fail_open(self):
        import httpx
        import respx
        from guardex import GuardExClient
        from guardex.exceptions import GuardExAPIError

        with respx.mock(base_url="http://test") as mock:
            route = mock.post("/v1/classify").mock(return_value=httpx.Response(404))
            client = GuardExClient(base_url="http://test", fail_open=True, max_retries=2)
            with pytest.raises(GuardExAPIError) as exc_info:
                client.classify("hi")
            assert exc_info.value.status_code == 404
            assert route.call_count == 1


class TestGuardModeSelection:
    """Server mode whenever a key or URL is configured anywhere; local otherwise."""

    def test_env_base_url_selects_server_mode(self, monkeypatch):
        monkeypatch.setenv("GUARDEX_BASE_URL", "http://envserver:9")
        monkeypatch.delenv("GUARDEX_API_KEY", raising=False)
        from guardex import Guard

        g = Guard()
        assert not g._is_local_mode()
        assert g._client.base_url == "http://envserver:9"

    def test_policy_base_url_selects_server_mode(self, monkeypatch):
        monkeypatch.delenv("GUARDEX_BASE_URL", raising=False)
        monkeypatch.delenv("GUARDEX_API_KEY", raising=False)
        from guardex import Guard, GuardExPolicy

        g = Guard(policy=GuardExPolicy(base_url="http://localhost:8001"))
        assert not g._is_local_mode()

    def test_no_config_selects_local_mode(self, monkeypatch):
        monkeypatch.delenv("GUARDEX_BASE_URL", raising=False)
        monkeypatch.delenv("GUARDEX_API_KEY", raising=False)
        pytest.importorskip("numpy")
        from guardex import Guard

        g = Guard()
        assert g._is_local_mode()


class TestDegradedPropagation:
    """Guard.screen() must carry degraded=True through result reconstruction."""

    def test_screen_propagates_degraded(self):
        import httpx
        import respx
        from guardex import Guard

        with respx.mock(base_url="http://test") as mock:
            mock.post("/v1/screen").mock(return_value=httpx.Response(500))
            with patch("guardex.client.time.sleep"):
                g = Guard(base_url="http://test", fail_open=True)
                result = g.screen("hello")
        assert result.degraded is True
        assert result.action == "pass"


class TestCascadeModeEnvValidation:
    """Invalid GUARDEX_CASCADE_MODE must fall back to safety, never speed."""

    def test_invalid_value_falls_back_to_safety(self, monkeypatch):
        monkeypatch.setenv("GUARDEX_CASCADE_MODE", "Speedy")
        from guardex._engine.settings import LocalSettings

        assert LocalSettings().cascade_mode == "safety"

    def test_case_insensitive_valid_value(self, monkeypatch):
        monkeypatch.setenv("GUARDEX_CASCADE_MODE", "SPEED")
        from guardex._engine.settings import LocalSettings

        assert LocalSettings().cascade_mode == "speed"


class TestLeetNormalization:
    """Leet expansion must not corrupt ordinary numeric or punctuated text."""

    def test_benign_numerics_untouched(self):
        from guardex._engine.ml.text_normalizer import normalize_for_classification

        assert normalize_for_classification("I have 3 cats and 5 dogs") == "I have 3 cats and 5 dogs"
        assert normalize_for_classification("win $500 today") == "win $500 today"

    def test_leet_words_expand(self):
        from guardex._engine.ml.text_normalizer import normalize_for_classification

        assert normalize_for_classification("k1ll them") == "kill them"
        assert normalize_for_classification("h@te speech") == "hate speech"

    def test_trailing_punctuation_untouched(self):
        from guardex._engine.ml.text_normalizer import normalize_for_classification

        assert normalize_for_classification("hello!") == "hello!"


class TestAmbiguousPiiContextGating:
    """Generic digit patterns stay below threshold without nearby context."""

    def test_bare_nine_digits_below_default_threshold(self):
        from guardex._engine.services.pii_regex import regex_detect

        res = regex_detect("order number 123456789 confirmed", ["ssn"])
        assert res
        assert all(e["score"] < 0.7 for e in res)

    def test_ssn_with_context_crosses_threshold(self):
        from guardex._engine.services.pii_regex import context_enhance, regex_detect

        text = "my SSN is 123-45-6789"
        res = regex_detect(text, ["ssn"])
        boosted = context_enhance(text, res)
        assert boosted
        assert boosted[0]["score"] >= 0.7

    def test_distinctive_patterns_keep_high_score(self):
        from guardex._engine.services.pii_regex import regex_detect

        res = regex_detect("reach me at jane.doe@example.com", ["email"])
        assert res
        assert res[0]["score"] >= 0.85


class TestPiiViolationEmptyEntities:
    """Blocking with no entity details must not produce '0 PII entities (types: )'."""

    def test_empty_entities_message(self):
        from guardex.exceptions import PIIViolation

        e = PIIViolation(stage="input", entities_found=[])
        assert "0 PII entities" not in str(e)
        assert "pii_action='mask'" in str(e)


class TestClassifierMessageShapes:
    """Dict-shaped messages must be screened, not silently skipped."""

    def test_dict_messages_are_classified(self):
        import httpx
        import respx
        from guardex.classifier import LlamaGuardClassifier
        from guardex.policy import GuardExPolicy

        unsafe = {"safe": False, "category": "S1", "categories": ["S1"], "confidence": 0.99}
        with respx.mock(base_url="http://test") as mock:
            mock.post("/v1/classify").mock(return_value=httpx.Response(200, json=unsafe))
            clf = LlamaGuardClassifier(GuardExPolicy(base_url="http://test"))
            result = clf.classify([{"role": "user", "content": "bad content"}])
        assert result.safe is False
        assert result.category == "S1"

    def test_plain_strings_are_classified(self):
        import httpx
        import respx
        from guardex.classifier import LlamaGuardClassifier
        from guardex.policy import GuardExPolicy

        unsafe = {"safe": False, "category": "S9", "categories": ["S9"], "confidence": 0.9}
        with respx.mock(base_url="http://test") as mock:
            mock.post("/v1/classify").mock(return_value=httpx.Response(200, json=unsafe))
            clf = LlamaGuardClassifier(GuardExPolicy(base_url="http://test"))
            result = clf.classify(["bad content"])
        assert result.safe is False
