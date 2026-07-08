"""Tests that public optional imports resolve and unknown attributes raise."""

from __future__ import annotations

import warnings

import pytest


class TestGuardedLLMImport:
    def test_import_succeeds_without_deprecation(self) -> None:
        """GuardedLLM is the official LangChain wrapper — should import without
        firing a deprecation warning.

        Skipped with a visible reason when langchain-core isn't installed,
        instead of silently swallowing the ImportError.
        """
        pytest.importorskip("langchain_core")

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            from guardex import GuardedLLM  # noqa: F401

            deprecation_warnings = [
                x for x in w if issubclass(x.category, DeprecationWarning)
                and "GuardedLLM" in str(x.message)
            ]
            assert len(deprecation_warnings) == 0


class TestGuardExCallbackHandlerImport:
    def test_import_succeeds(self) -> None:
        """GuardExCallbackHandler should import cleanly."""
        pytest.importorskip("langchain_core")
        from guardex import GuardExCallbackHandler  # noqa: F401

        assert GuardExCallbackHandler is not None


class TestLlamaGuardClassifierImport:
    def test_import_succeeds(self) -> None:
        """LlamaGuardClassifier should import cleanly."""
        from guardex import LlamaGuardClassifier  # noqa: F401

        assert LlamaGuardClassifier is not None


class TestNonExistentAttribute:
    def test_raises_attribute_error(self) -> None:
        import guardex

        with pytest.raises(AttributeError, match="no attribute"):
            _ = guardex.NonExistentThing  # noqa: B018
