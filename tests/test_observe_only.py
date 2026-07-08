# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 GuardEx
"""observe-only semantics: block_on_unsafe_* gates the classifier verdict only.

Injection, topic scope, safety routes, and pii_action="block" are independent
controls that always enforce, even when block_on_unsafe_input=False.
"""

from guardex.guard import _enforce_block, _block_category
from guardex.policy import GuardExPolicy
from guardex._types import (
    ClassifyResult,
    PIIResult,
    PIIEntity,
    ScopeResult,
    SafetyRouteOutcome,
    ScreenResult,
)


def _result(
    *,
    action="block",
    category=None,
    safe=False,
    scope=None,
    safety_route=None,
    pii=None,
):
    return ScreenResult(
        gate="input",
        action=action,
        classify=ClassifyResult(safe=safe, category=category),
        pii=pii or PIIResult(has_pii=False),
        text="x",
        scope=scope,
        safety_route=safety_route,
    )


OBSERVE = GuardExPolicy(block_on_unsafe_input=False, block_on_unsafe_output=False)
ENFORCE = GuardExPolicy(block_on_unsafe_input=True, block_on_unsafe_output=True)


def test_classifier_block_downgraded_in_observe_mode():
    r = _result(category="S1", safe=False)
    assert _enforce_block(r, "input", ENFORCE) is True
    assert _enforce_block(r, "input", OBSERVE) is False


def test_injection_always_enforced():
    r = _result(category="injection", safe=False)
    assert _enforce_block(r, "input", OBSERVE) is True


def test_scope_always_enforced():
    r = _result(safe=True, action="block", scope=ScopeResult(allowed=False))
    assert _enforce_block(r, "input", OBSERVE) is True


def test_safety_route_block_always_enforced():
    route = SafetyRouteOutcome(matched=True, route_name="secrets", action="block")
    r = _result(safe=True, action="block", safety_route=route)
    assert _enforce_block(r, "input", OBSERVE) is True


def test_pii_block_always_enforced():
    pol = GuardExPolicy(block_on_unsafe_input=False, pii_action="block")
    pii = PIIResult(has_pii=True, entities=[PIIEntity("a@b.co", "email", 1.0, 0, 6)])
    r = _result(safe=True, action="block", pii=pii)
    assert _enforce_block(r, "input", pol) is True


def test_pii_mask_not_treated_as_block_source():
    # mask policy: a classifier block should still downgrade in observe mode
    pol = GuardExPolicy(block_on_unsafe_input=False, pii_action="mask")
    pii = PIIResult(has_pii=True, masked_text="[EMAIL]")
    r = _result(category="S1", safe=False, action="block", pii=pii)
    assert _enforce_block(r, "input", pol) is False


def test_output_gate_uses_output_flag():
    r = _result(category="S1", safe=False)
    mixed = GuardExPolicy(block_on_unsafe_input=True, block_on_unsafe_output=False)
    assert _enforce_block(r, "output", mixed) is False
    assert _enforce_block(r, "tool_output", mixed) is False
    assert _enforce_block(r, "input", mixed) is True


def test_block_category_falls_back_to_source():
    assert _block_category(_result(category="S1")) == "S1"
    assert _block_category(_result(category="injection")) == "injection"
    assert _block_category(_result(safe=True, scope=ScopeResult(allowed=False))) == "scope"
    route = SafetyRouteOutcome(matched=True, route_name="secrets", action="block")
    assert _block_category(_result(safe=True, safety_route=route)) == "secrets"
