# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 GuardEx
"""GuardExContext -- Context types for context-aware filtering.

Contexts are frozen (immutable) value objects that describe the deployment,
user, and request dimensions of a GuardEx screening call. They serve as
cache keys for resolved policies and are serialized to HTTP headers.

Usage::

    from guardex.context import (
        GuardExContext, DeploymentContext, UserContext, RequestContext,
        AuthStatus, UserRole, Region, Industry, RequestType,
    )

    ctx = GuardExContext(
        deployment=DeploymentContext.PRODUCTION,
        user=UserContext(region=Region.EU, industry=Industry.HEALTHCARE),
        request=RequestContext(request_type=RequestType.CHAT),
    )
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional, Dict, Tuple


class DeploymentContext(str, Enum):
    """Deployment environment context.

    Each environment has a built-in policy profile:
      - DEVELOPMENT: lenient, fast feedback, fail_open=True
      - STAGING: production-like, all guards, detailed logging
      - PRODUCTION: strict, optimized latency, fail_open=False
      - DEMO: showcase mode, masking visible, speed cascade
      - COMPLIANCE: maximum strictness, all entities/categories, audit
    """
    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"
    DEMO = "demo"
    COMPLIANCE = "compliance"


class AuthStatus(str, Enum):
    """User authentication status."""
    AUTHENTICATED = "authenticated"
    ANONYMOUS = "anonymous"
    SERVICE = "service"


class UserRole(str, Enum):
    """User role for access-level policy tuning."""
    ADMIN = "admin"
    USER = "user"
    SERVICE = "service"
    AUDITOR = "auditor"


class Region(str, Enum):
    """Geographic region mapping to regulatory frameworks."""
    US = "us"
    EU = "eu"
    UK = "uk"
    CA = "ca"
    APAC = "apac"
    GLOBAL = "global"


class Industry(str, Enum):
    """Industry vertical with compliance requirements."""
    GENERAL = "general"
    HEALTHCARE = "healthcare"
    FINANCE = "finance"
    EDUCATION = "education"
    GOVERNMENT = "government"
    LEGAL = "legal"


class RequestType(str, Enum):
    """Type of request being processed."""
    CHAT = "chat"
    TOOL_CALL = "tool_call"
    RAG_RETRIEVAL = "rag_retrieval"
    RAG_GENERATION = "rag_generation"
    BATCH = "batch"
    EMBEDDING = "embedding"


@dataclass(frozen=True)
class UserContext:
    """User-level context for policy resolution.

    Parameters
    ----------
    auth_status : AuthStatus
        Whether the user is authenticated, anonymous, or a service account.
    role : UserRole
        The user's role (admin, user, service, auditor).
    region : Region
        Geographic region for regulatory compliance (GDPR, CCPA, etc.).
    industry : Industry
        Industry vertical for compliance (HIPAA, PCI-DSS, etc.).
    trust_score : float, optional
        User trust score from 0.0 (untrusted) to 1.0 (fully trusted).
        When set, modifies PII thresholds proportionally.
    """
    auth_status: AuthStatus = AuthStatus.AUTHENTICATED
    role: UserRole = UserRole.USER
    region: Region = Region.US
    industry: Industry = Industry.GENERAL
    trust_score: Optional[float] = None

    def __post_init__(self):
        if self.trust_score is not None and not (0.0 <= self.trust_score <= 1.0):
            raise ValueError(
                f"trust_score must be between 0.0 and 1.0, got {self.trust_score}"
            )


@dataclass(frozen=True)
class RequestContext:
    """Request-level context for policy resolution.

    Parameters
    ----------
    stage : str
        Processing stage: "input" or "output".
    request_type : RequestType
        The type of request (chat, tool_call, rag, batch, etc.).
    streaming : bool
        Whether this is a streaming request.
    has_system_prompt : bool
        Whether the request includes a system prompt.
    tool_names : tuple[str, ...]
        Names of tools being invoked (for tool_call type).
    """
    stage: str = "input"
    request_type: RequestType = RequestType.CHAT
    streaming: bool = False
    has_system_prompt: bool = False
    tool_names: Tuple[str, ...] = ()


@dataclass(frozen=True)
class GuardExContext:
    """Complete context for a GuardEx screening request.

    Composes deployment, user, and request contexts into a single
    immutable object. Serves as a cache key for resolved policies
    and serializes to HTTP headers for server-side resolution.

    Parameters
    ----------
    deployment : DeploymentContext
        The deployment environment (development, staging, production, etc.).
    user : UserContext
        User-level context (auth, role, region, industry).
    request : RequestContext
        Request-level context (stage, type, streaming).
    metadata : dict
        Additional key-value metadata (passed through, not used in resolution).

    Examples
    --------
    >>> ctx = GuardExContext(
    ...     deployment=DeploymentContext.PRODUCTION,
    ...     user=UserContext(region=Region.EU, industry=Industry.HEALTHCARE),
    ... )
    >>> key = ctx.cache_key()  # returns a 16-char hex string
    """
    deployment: DeploymentContext = DeploymentContext.PRODUCTION
    user: UserContext = field(default_factory=UserContext)
    request: RequestContext = field(default_factory=RequestContext)
    metadata: Dict[str, str] = field(default_factory=dict)

    def cache_key(self) -> str:
        """Deterministic hash for caching resolved policies.

        Returns a 16-character hex string. Same context always produces
        the same key. Metadata is excluded from the key because it
        does not affect policy resolution.
        """
        data = {
            "deployment": self.deployment.value,
            "user": {
                "auth_status": self.user.auth_status.value,
                "role": self.user.role.value,
                "region": self.user.region.value,
                "industry": self.user.industry.value,
                "trust_score": self.user.trust_score,
            },
            "request": {
                "stage": self.request.stage,
                "request_type": self.request.request_type.value,
                "streaming": self.request.streaming,
                "has_system_prompt": self.request.has_system_prompt,
                "tool_names": list(self.request.tool_names),
            },
        }
        raw = json.dumps(data, sort_keys=True)
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def to_header(self) -> str:
        """Serialize to a compact JSON string for the X-GuardEx-Context header."""
        return json.dumps(asdict(self), sort_keys=True, default=str)

    @classmethod
    def from_header(cls, header: str) -> "GuardExContext":
        """Deserialize from the X-GuardEx-Context header value.

        Gracefully handles missing or unknown fields by falling back
        to defaults. This ensures forward compatibility as new context
        fields are added.
        """
        data = json.loads(header)

        user_data = data.get("user", {})
        request_data = data.get("request", {})

        return cls(
            deployment=DeploymentContext(data.get("deployment", "production")),
            user=UserContext(
                auth_status=AuthStatus(user_data.get("auth_status", "authenticated")),
                role=UserRole(user_data.get("role", "user")),
                region=Region(user_data.get("region", "us")),
                industry=Industry(user_data.get("industry", "general")),
                trust_score=user_data.get("trust_score"),
            ),
            request=RequestContext(
                stage=request_data.get("stage", "input"),
                request_type=RequestType(request_data.get("request_type", "chat")),
                streaming=request_data.get("streaming", False),
                has_system_prompt=request_data.get("has_system_prompt", False),
                tool_names=tuple(request_data.get("tool_names", ())),
            ),
            metadata=data.get("metadata", {}),
        )
