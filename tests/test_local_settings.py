# tests/test_local_settings.py
"""Tests for guardex._engine.settings — local (in-process) configuration."""

from guardex._engine.settings import LocalSettings, load_local_settings


def test_default_settings_use_expected_model_repos():
    """LocalSettings defaults point at the canonical model repositories
    used by GuardEx in-process mode (toxicity, PII, topic-scope, Ollama)."""
    s = LocalSettings()
    assert s.onnx_hf_repo == "AtliQ-Technologies/toxicity-fast-onnx"
    assert s.gliner_model == "nvidia/gliner-pii"
    assert s.topic_scope_model == "sentence-transformers/all-MiniLM-L6-v2"
    assert s.ollama_url == "http://localhost:11434"
    assert s.ollama_model == "llama-guard3:1b"
    assert s.fail_open is False


def test_env_var_overrides_ollama_url(monkeypatch):
    """GUARDEX_OLLAMA_URL env var must override the default ollama_url."""
    monkeypatch.setenv("GUARDEX_OLLAMA_URL", "http://myhost:11434")
    s = LocalSettings()
    assert s.ollama_url == "http://myhost:11434"


def test_load_local_settings_returns_instance():
    """load_local_settings() returns a LocalSettings instance (not a dict)."""
    s = load_local_settings()
    assert isinstance(s, LocalSettings)
