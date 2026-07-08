# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 GuardEx
"""Built-in context profiles -- default policy overrides per context value.

These profiles encode well-known compliance requirements and operational
best practices. They are applied automatically based on the context
dimensions provided in a GuardExContext.

Profiles are defined as code (not database) because they represent
security-critical defaults that should be auditable, tested, and
versioned alongside the SDK.
"""

from __future__ import annotations

from .policy_override import PolicyOverride
from .context import (
    DeploymentContext, Region, Industry,
    AuthStatus, RequestType,
)
from .policy import ALL_CATEGORIES, DEFAULT_PII_ENTITIES


DEPLOYMENT_PROFILES: dict[DeploymentContext, PolicyOverride] = {

    DeploymentContext.DEVELOPMENT: PolicyOverride(
        fail_open=True,
        cascade_mode="speed",
        pii_threshold=0.9,
        detailed_logging=True,
        audit_logging=False,
    ),

    DeploymentContext.STAGING: PolicyOverride(
        pii_enabled=True,
        block_on_unsafe_input=True,
        block_on_unsafe_output=True,
        cascade_mode="safety",
        audit_logging=True,
    ),

    DeploymentContext.PRODUCTION: PolicyOverride(
        pii_enabled=True,
        block_on_unsafe_input=True,
        block_on_unsafe_output=True,
        fail_open=False,
        cascade_mode="safety",
        audit_logging=True,
    ),

    DeploymentContext.DEMO: PolicyOverride(
        pii_enabled=True,
        block_on_unsafe_input=True,
        block_on_unsafe_output=True,
        pii_action="mask",
        cascade_mode="speed",
        detailed_logging=True,
    ),

    DeploymentContext.COMPLIANCE: PolicyOverride(
        pii_enabled=True,
        pii_entities_add=list(DEFAULT_PII_ENTITIES),
        pii_action="block",
        pii_threshold=0.3,
        block_on_unsafe_input=True,
        block_on_unsafe_output=True,
        blocked_categories_add=list(ALL_CATEGORIES),
        fail_open=False,
        cascade_mode="safety",
        audit_logging=True,
        # detailed_logging intentionally omitted: compliance contexts must not
        # log plaintext user prompts - only hashed audit records are permitted.
    ),
}


REGION_PROFILES: dict[Region, PolicyOverride] = {

    Region.EU: PolicyOverride(
        pii_entities_add=[
            "national_id", "tax_id", "iban",
            "eu_passport", "gdpr_special_category",
        ],
        pii_action="block",
        pii_threshold=0.5,
        audit_logging=True,
    ),

    Region.UK: PolicyOverride(
        pii_entities_add=[
            "national_id", "nhs_number", "ni_number",
        ],
        pii_action="block",
        pii_threshold=0.5,
        audit_logging=True,
    ),

    Region.CA: PolicyOverride(
        pii_entities_add=[
            "sin_number", "health_card",
        ],
        pii_threshold=0.5,
        audit_logging=True,
    ),

    Region.US: PolicyOverride(),

    Region.APAC: PolicyOverride(
        pii_entities_add=["aadhaar", "pan_card"],
    ),

    Region.GLOBAL: PolicyOverride(
        pii_entities_add=[
            "national_id", "tax_id", "iban", "eu_passport",
            "sin_number", "health_card", "nhs_number", "ni_number",
            "aadhaar", "pan_card",
        ],
        pii_action="block",
        pii_threshold=0.3,
        audit_logging=True,
    ),
}


INDUSTRY_PROFILES: dict[Industry, PolicyOverride] = {

    Industry.HEALTHCARE: PolicyOverride(
        pii_entities_add=[
            "medical_record_number", "insurance_id",
            "diagnosis_code", "prescription", "patient_id",
            "health_plan_id", "medical_device_id",
        ],
        pii_action="block",
        pii_threshold=0.4,
        audit_logging=True,
    ),

    Industry.FINANCE: PolicyOverride(
        pii_entities_add=[
            "credit_card", "bank_account", "routing_number",
            "investment_account", "tax_id",
        ],
        pii_action="block",
        pii_threshold=0.4,
        blocked_categories_add=["S6"],
        audit_logging=True,
    ),

    Industry.EDUCATION: PolicyOverride(
        pii_entities_add=[
            "student_id", "parent_name", "school_name",
            "grade_record", "disciplinary_record",
        ],
        pii_threshold=0.5,
        blocked_categories_add=["S3", "S4", "S12"],
        audit_logging=True,
    ),

    Industry.GOVERNMENT: PolicyOverride(
        pii_entities_add=[
            "clearance_level", "government_id",
            "classified_marking",
        ],
        pii_action="block",
        pii_threshold=0.3,
        blocked_categories_add=list(ALL_CATEGORIES),
        fail_open=False,
        cascade_mode="safety",
        audit_logging=True,
    ),

    Industry.LEGAL: PolicyOverride(
        pii_entities_add=[
            "case_number", "bar_number", "client_id",
        ],
        pii_action="block",
        audit_logging=True,
    ),

    Industry.GENERAL: PolicyOverride(),
}


AUTH_PROFILES: dict[AuthStatus, PolicyOverride] = {

    AuthStatus.ANONYMOUS: PolicyOverride(
        pii_threshold=0.5,
        blocked_categories_add=["S6"],
    ),

    AuthStatus.AUTHENTICATED: PolicyOverride(),

    AuthStatus.SERVICE: PolicyOverride(
        fail_open=False,
        cascade_mode="speed",
    ),
}


REQUEST_TYPE_PROFILES: dict[RequestType, PolicyOverride] = {

    RequestType.TOOL_CALL: PolicyOverride(
        block_on_unsafe_input=True,
        pii_threshold=0.5,
        blocked_categories_add=["S14"],
    ),

    RequestType.RAG_RETRIEVAL: PolicyOverride(
        pii_enabled=True,
    ),

    RequestType.RAG_GENERATION: PolicyOverride(
        block_on_unsafe_output=True,
    ),

    RequestType.BATCH: PolicyOverride(
        cascade_mode="speed",
        timeout=60,
    ),

    RequestType.EMBEDDING: PolicyOverride(
        block_on_unsafe_input=False,
        block_on_unsafe_output=False,
        pii_enabled=True,
    ),

    RequestType.CHAT: PolicyOverride(),
}
