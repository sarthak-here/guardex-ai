# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 GuardEx
"""Configuration for the grounding engine."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class GroundingMode(str, Enum):
    SPEED = "speed"
    ACCURACY = "accuracy"


@dataclass
class GroundingConfig:
    mode: GroundingMode = GroundingMode.ACCURACY
    grounded_threshold: float = 0.55
    contradiction_threshold: float = 0.7
    faithfulness_pass_threshold: float = 0.5
    min_sentence_length: int = 20
    hybrid_neutral_threshold: float = 0.65
