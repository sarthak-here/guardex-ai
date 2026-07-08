# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 GuardEx
"""Built-in classifier provider wrapping existing LlamaGuard service."""

from __future__ import annotations

from typing import Any

from guardex._engine.services import classifier as classifier_service


class LlamaGuardClassifierProvider:
    """Safety classification using LlamaGuard via Ollama.

    Parameterized: each instance can target a different Ollama model.
    """

    def __init__(self, name: str = "guardex-shield-v1", ollama_model: str | None = None):
        self.name = name
        self.ollama_model = ollama_model

    async def classify(
        self,
        text: str,
        stage: str = "input",
        categories: list[str] | None = None,
        **_extra: Any,
    ) -> dict[str, Any]:
        return await classifier_service.classify(
            text=text,
            stage=stage,
            categories=categories,
            model_name=self.ollama_model,
        )
