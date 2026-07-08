# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 GuardEx
"""EffectiveConfig - typed representation of merged dashboard + code config."""

from dataclasses import dataclass, field
from typing import Dict, List, Literal, Optional

from ._types import CATEGORY_DESCRIPTIONS as CATEGORY_LABELS  # canonical names


@dataclass
class PIIMergedConfig:
    """Merged PII configuration resolved from dashboard and code sources.

    Attributes
    ----------
    enabled:
        Whether PII detection is active. Default ``True``.
    entities:
        PII entity types being detected (union of dashboard + code lists).
    action:
        What to do when PII is detected: ``"mask"`` replaces it with a
        placeholder, ``"block"`` raises ``PIIViolation``. Default ``"mask"``.
    threshold:
        Detection confidence threshold (0.0–1.0). Default ``0.85``.
    """
    enabled: bool = True
    entities: List[str] = field(default_factory=list)
    action: Literal["mask", "block"] = "mask"
    threshold: float = 0.85


@dataclass
class ContentMergedConfig:
    """Merged content moderation configuration resolved from dashboard and code sources.

    Attributes
    ----------
    enabled:
        Whether content moderation is active. Default ``True``.
    blocked_categories:
        LlamaGuard category codes blocked in the merged config (e.g. ``["S1", "S4"]``).
    check_input:
        Whether user input is screened. Default ``True``.
    check_output:
        Whether LLM output is screened. Default ``True``.
    """
    enabled: bool = True
    blocked_categories: List[str] = field(default_factory=list)
    check_input: bool = True
    check_output: bool = True


@dataclass
class EffectiveConfig:
    """Merged effective config from dashboard + code sources.

    Attributes
    ----------
    pii:
        Merged PII configuration.
    content:
        Merged content moderation configuration.
    sources:
        Dict mapping each field to its source (``"dashboard"``, ``"code"``, or ``"both"``).
    conflicts:
        List of conflict messages (e.g. code tried to loosen a dashboard policy).
    last_code_config_seen_at:
        ISO 8601 timestamp of the last code config snapshot received by the server.
        ``None`` if the server has not yet received a code-side config.
    last_dashboard_updated_at:
        ISO 8601 timestamp of the last dashboard policy update.
        ``None`` if no dashboard policy has been configured yet.
    """
    pii: PIIMergedConfig = field(default_factory=PIIMergedConfig)
    content: ContentMergedConfig = field(default_factory=ContentMergedConfig)
    sources: Dict[str, Dict[str, str]] = field(default_factory=dict)
    conflicts: List[str] = field(default_factory=list)
    last_code_config_seen_at: Optional[str] = None
    last_dashboard_updated_at: Optional[str] = None

    @classmethod
    def from_api_response(cls, data: Dict[str, object]) -> "EffectiveConfig":
        """Parse from GET /v1/config/effective response."""
        effective = data.get("effective", {})
        pii_data = effective.get("pii", {})
        content_data = effective.get("content_moderation", {})

        return cls(
            pii=PIIMergedConfig(
                enabled=pii_data.get("enabled", True),
                entities=pii_data.get("entities", []),
                action=pii_data.get("action", "mask"),
                threshold=pii_data.get("threshold", 0.85),
            ),
            content=ContentMergedConfig(
                enabled=content_data.get("enabled", True),
                blocked_categories=content_data.get("blocked_categories", []),
                check_input=content_data.get("check_input", True),
                check_output=content_data.get("check_output", True),
            ),
            sources=data.get("sources", {}),
            conflicts=data.get("conflicts", []),
            last_code_config_seen_at=data.get("last_code_config_seen_at"),
            last_dashboard_updated_at=data.get("last_dashboard_updated_at"),
        )

    def __repr__(self) -> str:
        return (
            f"EffectiveConfig(pii={self.pii.enabled}, "
            f"content={self.content.enabled}, "
            f"conflicts={len(self.conflicts)})"
        )

    def __str__(self) -> str:
        """Multi-line human-readable summary for ops dashboards / logs."""
        lines = ["[GuardEx] Effective config"]

        # PII section
        status = "ON" if self.pii.enabled else "OFF"
        lines.append(f"PII:      {status} | action: {self.pii.action} | entities: {len(self.pii.entities)}")
        entity_sources = self.sources.get("pii.entities", {})
        for entity in self.pii.entities:
            src = entity_sources.get(entity, "unknown")
            lines.append(f"  {entity:<24} ({src})")

        # Content section
        status = "ON" if self.content.enabled else "OFF"
        lines.append(f"Content:  {status} | blocked: {len(self.content.blocked_categories)} categories")
        cat_sources = self.sources.get("content_moderation.blocked_categories", {})
        for cat in self.content.blocked_categories:
            label = CATEGORY_LABELS.get(cat, cat)
            src = cat_sources.get(cat, "unknown")
            lines.append(f"  {cat:<4} {label:<24} ({src})")

        # Conflicts
        if self.conflicts:
            lines.append("")
            lines.append("WARNINGS:")
            for c in self.conflicts:
                lines.append(f"  ! {c}")

        return "\n".join(lines)
