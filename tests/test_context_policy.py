"""Tests for context-aware policy resolution.

Validates the four composition laws:
  Law 1: Monotonic security (never weakens)
  Law 2: Dimensional independence (order doesn't matter)
  Law 3: Explicit override only (can only add restrictions)
  Law 4: Default passthrough (unset fields inherit)
"""

import pytest
from guardex.context import (
    GuardExContext, DeploymentContext, UserContext, RequestContext,
    AuthStatus, UserRole, Region, Industry, RequestType,
)
from guardex.policy import GuardExPolicy
from guardex.policy_override import PolicyOverride
from guardex.policy_resolver import resolve_policy, CachedPolicyResolver


# ============================================================
# Fixtures
# ============================================================

@pytest.fixture
def base_policy():
    """A typical base policy."""
    return GuardExPolicy(
        api_key="gx_test_123",
        pii_enabled=True,
        pii_entities=["email", "phone_number", "ssn"],
        pii_action="mask",
        pii_threshold=0.7,
        block_on_unsafe_input=True,
        block_on_unsafe_output=True,
        blocked_categories=["S1", "S3", "S4"],
        fail_open=False,
        timeout=30,
    )


# ============================================================
# Law 1: Monotonic Security
# ============================================================

class TestMonotonicSecurity:
    """No context should weaken the base policy."""

    def test_development_cannot_disable_pii(self, base_policy):
        """Development context sets fail_open=True but cannot disable PII."""
        ctx = GuardExContext(deployment=DeploymentContext.DEVELOPMENT)
        effective = resolve_policy(base_policy, ctx)
        assert effective.pii_enabled is True

    def test_threshold_only_decreases(self, base_policy):
        """Threshold composition takes MIN (more sensitive)."""
        ctx = GuardExContext(
            user=UserContext(region=Region.EU),  # threshold=0.5
        )
        effective = resolve_policy(base_policy, ctx)
        assert effective.pii_threshold <= base_policy.pii_threshold

    def test_entities_only_grow(self, base_policy):
        """Entity set can only grow (UNION), never shrink."""
        ctx = GuardExContext(
            user=UserContext(industry=Industry.HEALTHCARE),
        )
        effective = resolve_policy(base_policy, ctx)
        assert set(base_policy.pii_entities).issubset(set(effective.pii_entities))
        assert "medical_record_number" in effective.pii_entities

    def test_categories_only_grow(self, base_policy):
        """Category set can only grow (UNION), never shrink."""
        ctx = GuardExContext(
            user=UserContext(industry=Industry.FINANCE),
        )
        effective = resolve_policy(base_policy, ctx)
        assert set(base_policy.blocked_categories).issubset(set(effective.blocked_categories))
        assert "S6" in effective.blocked_categories

    def test_action_only_escalates(self, base_policy):
        """Action severity can only increase (block > mask > none)."""
        ctx = GuardExContext(
            user=UserContext(region=Region.EU),  # pii_action=block
        )
        effective = resolve_policy(base_policy, ctx)
        assert effective.pii_action == "block"  # Escalated from mask

    def test_fail_open_strict_wins(self, base_policy):
        """fail_open uses AND: False (strict) wins."""
        # Base is fail_open=False. Development sets fail_open=True.
        # But adding production context with fail_open=False wins.
        base = GuardExPolicy(api_key="test", fail_open=True)
        ctx = GuardExContext(deployment=DeploymentContext.PRODUCTION)
        effective = resolve_policy(base, ctx)
        assert effective.fail_open is False


# ============================================================
# Law 2: Dimensional Independence
# ============================================================

class TestDimensionalIndependence:
    """Context dimensions compose independently."""

    def test_region_and_industry_compose(self, base_policy):
        """EU region + Healthcare industry = both entity sets merged."""
        ctx = GuardExContext(
            user=UserContext(region=Region.EU, industry=Industry.HEALTHCARE),
        )
        effective = resolve_policy(base_policy, ctx)
        # EU entities
        assert "national_id" in effective.pii_entities
        assert "iban" in effective.pii_entities
        # Healthcare entities
        assert "medical_record_number" in effective.pii_entities
        assert "insurance_id" in effective.pii_entities

    def test_deployment_and_user_compose(self, base_policy):
        """Compliance deployment + anonymous user = maximum strictness."""
        ctx = GuardExContext(
            deployment=DeploymentContext.COMPLIANCE,
            user=UserContext(auth_status=AuthStatus.ANONYMOUS),
        )
        effective = resolve_policy(base_policy, ctx)
        assert effective.pii_action == "block"
        assert effective.pii_threshold <= 0.3  # Compliance sets 0.3
        assert "S6" in effective.blocked_categories  # Anonymous adds S6

    def test_all_dimensions_compose(self, base_policy):
        """All three dimensions compose without conflict."""
        ctx = GuardExContext(
            deployment=DeploymentContext.PRODUCTION,
            user=UserContext(
                region=Region.EU,
                industry=Industry.HEALTHCARE,
                auth_status=AuthStatus.AUTHENTICATED,
            ),
            request=RequestContext(request_type=RequestType.TOOL_CALL),
        )
        effective = resolve_policy(base_policy, ctx)
        # Production + EU + Healthcare + Tool Call
        assert effective.pii_action == "block"
        assert "S14" in effective.blocked_categories  # Tool call
        assert "national_id" in effective.pii_entities  # EU
        assert "medical_record_number" in effective.pii_entities  # Healthcare


# ============================================================
# Law 3: Explicit Override Only
# ============================================================

class TestExplicitOverrideOnly:
    """Custom rules can only add restrictions."""

    def test_custom_rule_adds_entities(self, base_policy):
        """Custom rule adds entities to the set."""
        custom = PolicyOverride(
            pii_entities_add=["custom_field_1", "custom_field_2"],
        )
        ctx = GuardExContext()
        effective = resolve_policy(base_policy, ctx, custom_rules=[custom])
        assert "custom_field_1" in effective.pii_entities
        assert "custom_field_2" in effective.pii_entities

    def test_custom_rule_tightens_threshold(self, base_policy):
        """Custom rule with lower threshold wins."""
        custom = PolicyOverride(pii_threshold=0.3)
        ctx = GuardExContext()
        effective = resolve_policy(base_policy, ctx, custom_rules=[custom])
        assert effective.pii_threshold == 0.3

    def test_custom_rule_higher_threshold_ignored(self, base_policy):
        """Custom rule with higher threshold does not loosen policy."""
        custom = PolicyOverride(pii_threshold=0.9)
        ctx = GuardExContext()
        effective = resolve_policy(base_policy, ctx, custom_rules=[custom])
        # 0.9 > 0.7, so base threshold wins (MIN)
        assert effective.pii_threshold == 0.7


# ============================================================
# Law 4: Default Passthrough
# ============================================================

class TestDefaultPassthrough:
    """Unset override fields inherit from base."""

    def test_empty_override_changes_nothing(self, base_policy):
        """An empty PolicyOverride has no effect."""
        custom = PolicyOverride()
        ctx = GuardExContext()
        effective = resolve_policy(base_policy, ctx, custom_rules=[custom])
        assert effective.pii_threshold == base_policy.pii_threshold
        assert effective.pii_action == base_policy.pii_action
        assert effective.pii_entities == base_policy.pii_entities

    def test_no_context_returns_base(self, base_policy):
        """Default context (all defaults) returns base policy unchanged."""
        ctx = GuardExContext()
        effective = resolve_policy(base_policy, ctx)
        # Production deployment profile adds some things but base US region
        # and general industry add nothing
        assert effective.pii_enabled == base_policy.pii_enabled


# ============================================================
# Backward Compatibility
# ============================================================

class TestBackwardCompatibility:
    """Existing usage without context must work unchanged."""

    def test_policy_without_context_unchanged(self):
        """GuardExPolicy works without any context features."""
        policy = GuardExPolicy(
            api_key="gx_test_123",
            pii_entities=["email"],
            blocked_categories=["S1"],
        )
        assert policy.pii_entities == ["email"]
        assert policy.blocked_categories == ["S1"]

    def test_resolve_with_default_context(self, base_policy):
        """Default GuardExContext produces deterministic result."""
        ctx1 = GuardExContext()
        ctx2 = GuardExContext()
        eff1 = resolve_policy(base_policy, ctx1)
        eff2 = resolve_policy(base_policy, ctx2)
        assert eff1.pii_entities == eff2.pii_entities
        assert eff1.blocked_categories == eff2.blocked_categories


# ============================================================
# Context Serialization
# ============================================================

class TestContextSerialization:
    """Context round-trips through HTTP header serialization."""

    def test_round_trip(self):
        """Context survives to_header -> from_header round trip."""
        original = GuardExContext(
            deployment=DeploymentContext.COMPLIANCE,
            user=UserContext(
                region=Region.EU,
                industry=Industry.HEALTHCARE,
                trust_score=0.85,
            ),
            request=RequestContext(
                request_type=RequestType.TOOL_CALL,
                streaming=True,
            ),
        )
        header = original.to_header()
        restored = GuardExContext.from_header(header)
        assert restored.deployment == original.deployment
        assert restored.user.region == original.user.region
        assert restored.user.industry == original.user.industry
        assert restored.user.trust_score == original.user.trust_score
        assert restored.request.request_type == original.request.request_type
        assert restored.request.streaming == original.request.streaming

    def test_cache_key_deterministic(self):
        """Same context always produces the same cache key."""
        ctx1 = GuardExContext(deployment=DeploymentContext.PRODUCTION)
        ctx2 = GuardExContext(deployment=DeploymentContext.PRODUCTION)
        assert ctx1.cache_key() == ctx2.cache_key()

    def test_cache_key_varies_with_context(self):
        """Different contexts produce different cache keys."""
        ctx_prod = GuardExContext(deployment=DeploymentContext.PRODUCTION)
        ctx_dev = GuardExContext(deployment=DeploymentContext.DEVELOPMENT)
        assert ctx_prod.cache_key() != ctx_dev.cache_key()


# ============================================================
# CachedPolicyResolver
# ============================================================

class TestCachedResolver:
    """CachedPolicyResolver caches and evicts correctly."""

    def test_cache_hit(self, base_policy):
        """Second resolve for same context is a cache hit."""
        resolver = CachedPolicyResolver(base_policy)
        ctx = GuardExContext(deployment=DeploymentContext.PRODUCTION)
        resolver.resolve(ctx)
        resolver.resolve(ctx)
        assert resolver.stats["hits"] == 1
        assert resolver.stats["misses"] == 1

    def test_cache_eviction(self, base_policy):
        """Cache evicts oldest when full."""
        resolver = CachedPolicyResolver(base_policy, max_cache_size=2)
        ctx1 = GuardExContext(deployment=DeploymentContext.DEVELOPMENT)
        ctx2 = GuardExContext(deployment=DeploymentContext.STAGING)
        ctx3 = GuardExContext(deployment=DeploymentContext.PRODUCTION)
        resolver.resolve(ctx1)
        resolver.resolve(ctx2)
        resolver.resolve(ctx3)  # Evicts ctx1
        assert resolver.stats["cache_size"] == 2

    def test_invalidate(self, base_policy):
        """Invalidate clears cache and stats."""
        resolver = CachedPolicyResolver(base_policy)
        resolver.resolve(GuardExContext())
        resolver.invalidate()
        assert resolver.stats["cache_size"] == 0
        assert resolver.stats["hits"] == 0


# ============================================================
# Specific Compliance Scenarios
# ============================================================

class TestComplianceScenarios:
    """Real-world compliance context compositions."""

    def test_hipaa_compliance(self, base_policy):
        """HIPAA: healthcare + compliance = maximum medical PII protection."""
        ctx = GuardExContext(
            deployment=DeploymentContext.COMPLIANCE,
            user=UserContext(industry=Industry.HEALTHCARE),
        )
        effective = resolve_policy(base_policy, ctx)
        assert effective.pii_action == "block"
        assert effective.pii_threshold <= 0.3
        assert "medical_record_number" in effective.pii_entities
        assert "insurance_id" in effective.pii_entities
        assert effective.fail_open is False

    def test_pci_dss_compliance(self, base_policy):
        """PCI-DSS: finance + production = block card data."""
        ctx = GuardExContext(
            deployment=DeploymentContext.PRODUCTION,
            user=UserContext(industry=Industry.FINANCE),
        )
        effective = resolve_policy(base_policy, ctx)
        assert effective.pii_action == "block"
        assert "credit_card" in effective.pii_entities
        assert "bank_account" in effective.pii_entities

    def test_gdpr_healthcare_combo(self, base_policy):
        """GDPR + HIPAA: EU healthcare = union of both entity sets."""
        ctx = GuardExContext(
            user=UserContext(
                region=Region.EU,
                industry=Industry.HEALTHCARE,
            ),
        )
        effective = resolve_policy(base_policy, ctx)
        # EU entities
        assert "national_id" in effective.pii_entities
        assert "iban" in effective.pii_entities
        # Healthcare entities
        assert "medical_record_number" in effective.pii_entities
        # Threshold: min(0.5 EU, 0.4 healthcare) = 0.4
        assert effective.pii_threshold == 0.4

    def test_coppa_education(self, base_policy):
        """COPPA: education = strict content categories for minors."""
        ctx = GuardExContext(
            user=UserContext(industry=Industry.EDUCATION),
        )
        effective = resolve_policy(base_policy, ctx)
        assert "S3" in effective.blocked_categories
        assert "S4" in effective.blocked_categories
        assert "S12" in effective.blocked_categories
        assert "student_id" in effective.pii_entities


# ============================================================
# PolicyOverride
# ============================================================

class TestPolicyOverride:
    """PolicyOverride utility methods."""

    def test_empty_check(self):
        """Empty override reports as empty."""
        assert PolicyOverride().is_empty() is True

    def test_non_empty_check(self):
        """Override with any field set reports as non-empty."""
        assert PolicyOverride(pii_enabled=True).is_empty() is False

    def test_entities_add_is_additive(self, base_policy):
        """pii_entities_add ADDS to existing, never replaces."""
        custom = PolicyOverride(pii_entities_add=["new_entity"])
        ctx = GuardExContext()
        effective = resolve_policy(base_policy, ctx, custom_rules=[custom])
        assert "email" in effective.pii_entities  # Original preserved
        assert "new_entity" in effective.pii_entities  # New added


# ============================================================
# UserContext Validation
# ============================================================

class TestUserContextValidation:

    def test_valid_trust_score(self):
        """Trust score within bounds is accepted."""
        user = UserContext(trust_score=0.5)
        assert user.trust_score == 0.5

    def test_invalid_trust_score_high(self):
        """Trust score above 1.0 raises ValueError."""
        with pytest.raises(ValueError):
            UserContext(trust_score=1.5)

    def test_invalid_trust_score_low(self):
        """Trust score below 0.0 raises ValueError."""
        with pytest.raises(ValueError):
            UserContext(trust_score=-0.1)
