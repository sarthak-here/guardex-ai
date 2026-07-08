# Context-Aware Policy Resolution

Define different safety policies for different deployment environments, user roles, geographic regions, and request types. GuardEx resolves the effective policy per request from the context you pass to `screen()`.

## Why Context-Aware Policies Matter

A single blanket policy cannot serve every deployment, user type, and regulatory jurisdiction at once:

- **GDPR compliance (EU)** requires stricter PII protection than general US usage
- **HIPAA (healthcare)** demands blocking PII entirely rather than masking it
- **Development environments** should fail gracefully to not block developers
- **Anonymous users** require tighter security than authenticated admins

Context-aware policies solve this by composing multiple policy layers, each activated based on the runtime context.

### Real-World Example: Healthcare in EU

```python
from guardex import Guard
from guardex.context import (
    GuardExContext, DeploymentContext, Region, Industry,
    UserContext, UserRole
)

guard = Guard()

# EU healthcare provider - automatically tightest settings
ctx = GuardExContext(
    deployment=DeploymentContext.PRODUCTION,
    user=UserContext(
        region=Region.EU,
        industry=Industry.HEALTHCARE,
        role=UserRole.USER
    )
)

# Result: GDPR + Healthcare entities, PII blocks (not masks)
result = guard.screen(user_input, context=ctx)
```

The effective policy will automatically:
- Enable PII detection (from PRODUCTION profile)
- Add EU-specific PII entities: `national_id`, `tax_id`, `iban`, `eu_passport` (from REGION profile)
- Add healthcare entities: medical record numbers, patient IDs (from INDUSTRY profile)
- Switch PII action from `mask` to `block` (from INDUSTRY profile)
- Reduce PII threshold to 0.4 (MIN of the EU 0.5 and HEALTHCARE 0.4 overlays)

## GuardExContext: The Core Data Model

`GuardExContext` is an immutable dataclass that captures all dimensions of your screening request.

### Complete Structure

```python
from guardex.context import (
    GuardExContext, DeploymentContext, UserContext, RequestContext,
    AuthStatus, UserRole, Region, Industry, RequestType
)

ctx = GuardExContext(
    # Which environment is this?
    deployment=DeploymentContext.PRODUCTION,

    # Who is the user?
    user=UserContext(
        auth_status=AuthStatus.AUTHENTICATED,
        role=UserRole.USER,
        region=Region.US,
        industry=Industry.GENERAL,
        trust_score=0.85  # optional: 0.0 (untrusted) to 1.0 (trusted)
    ),

    # What kind of request is this?
    request=RequestContext(
        stage="input",  # "input" or "output"
        request_type=RequestType.CHAT,
        streaming=False,
        has_system_prompt=False,
        tool_names=()  # for tool_call type
    ),

    # Additional metadata (not used in policy resolution)
    metadata={"user_id": "user_123", "session_id": "sess_456"}
)
```

All fields have sensible defaults, so you can create a minimal context and only set what differs from defaults:

```python
# Minimal context - all defaults except region
ctx = GuardExContext(
    user=UserContext(region=Region.EU)
)
```

### Cache Keys

Contexts produce deterministic cache keys, enabling efficient policy caching:

```python
ctx1 = GuardExContext(user=UserContext(region=Region.EU))
ctx2 = GuardExContext(user=UserContext(region=Region.EU))

assert ctx1.cache_key() == ctx2.cache_key()  # Same key → cached policy

ctx3 = GuardExContext(user=UserContext(region=Region.US))
assert ctx1.cache_key() != ctx3.cache_key()  # Different key → recompute
```

## Enumerations: Context Values

### DeploymentContext

The deployment environment, each with built-in policy defaults:

| Value | Use Case | Key Defaults |
|-------|----------|--------------|
| `DEVELOPMENT` | Local development, testing | `fail_open=True`, cascade `"speed"`, lenient thresholds |
| `STAGING` | Pre-production QA | Full safeguards, detailed logging, safety cascade |
| `PRODUCTION` | Live traffic | Strict, optimized latency, `fail_open=False` |
| `DEMO` | Demo/sales environment | Masking visible, speed cascade, security enabled |
| `COMPLIANCE` | Audit/compliance mode | Maximum strictness, block all categories, all entities |

### Region

Geographic regions with regulatory compliance requirements:

| Value | Regulations | Key Changes |
|-------|-------------|------------|
| `US` | Default, CCPA | Standard PII entities |
| `EU` | **GDPR**, DPA | Adds `national_id`, `tax_id`, `iban`, `eu_passport`, `gdpr_special_category`; blocks PII |
| `UK` | UK-GDPR, DPA | Adds `nhs_number`, `ni_number`, `national_id` |
| `CA` | PIPEDA | Adds `sin_number` (Social Insurance Number), `health_card` |
| `APAC` | Various (PDPA, etc.) | Adds region-specific IDs |
| `GLOBAL` | Strictest | Combines all regions' entities |

### Industry

Industry-specific compliance (HIPAA, PCI-DSS, SOX, etc.):

| Value | Standard | Key Changes |
|-------|----------|------------|
| `GENERAL` | Default | Standard entities |
| `HEALTHCARE` | **HIPAA**, HL7 | Adds medical record IDs, patient names, provider IDs; blocks PII |
| `FINANCE` | PCI-DSS, SOX | Adds payment card data, routing numbers, investment accounts; blocks S6 (specialized advice) |
| `EDUCATION` | FERPA | Adds student IDs, grades, transcripts |
| `GOVERNMENT` | Various | Adds SSN detection, security clearance levels |
| `LEGAL` | Attorney-client privilege | Adds case numbers, attorney names |

### AuthStatus

User authentication status:

| Value | Meaning |
|-------|---------|
| `AUTHENTICATED` | Logged-in user with verified identity |
| `ANONYMOUS` | No authentication (stricter policy) |
| `SERVICE` | Service-to-service account |

### UserRole

User's access level and responsibilities:

| Value | Meaning |
|-------|---------|
| `USER` | Standard end-user (default) |
| `ADMIN` | Administrator with elevated privileges |
| `SERVICE` | Service account |
| `AUDITOR` | Compliance/audit reviewer (all entities visible) |

### RequestType

Type of request being processed:

| Value | Meaning |
|-------|---------|
| `CHAT` | Standard conversation (default) |
| `TOOL_CALL` | LLM calling external tools |
| `RAG_RETRIEVAL` | RAG document retrieval phase |
| `RAG_GENERATION` | RAG response generation from retrieved docs |
| `BATCH` | Batch processing job |
| `EMBEDDING` | Vector embedding request |

## Semilattice Composition Rules

Policies are composed using **semilattice join operations**, which are mathematically guaranteed to be monotonically non-decreasing in strictness. Order of application does not matter.

### Composition Rules by Field Type

| Field Type | Composition | Example |
|-----------|------------|---------|
| **Boolean** (pii_enabled, block_on_unsafe_input, etc.) | **OR** - True wins | `base.pii_enabled=False` + `region.pii_enabled=True` = **True** |
| **Thresholds** (pii_threshold, timeout) | **MIN** - stricter wins | `base.threshold=0.9` + `region.threshold=0.5` = **0.5** |
| **Sets** (pii_entities, blocked_categories) | **UNION** - additive only | `base=[S1,S3]` + `region=[S3,S9]` = **[S1,S3,S9]** |
| **Actions** (pii_action) | **MAX_SEVERITY** - block > mask > none | `base="mask"` + `region="block"` = **"block"** |
| **fail_open** | **AND** - False/strict wins | `base=True` + `production=False` = **False** |
| **cascade_mode** | **MAX_STRICTNESS** - safety > speed | `base="speed"` + `production="safety"` = **"safety"** |

### Example Composition Trace

```python
from guardex import (
    resolve_policy, GuardExPolicy, GuardExContext,
    DeploymentContext, UserContext, Region, Industry,
)

# Base policy (project default)
base = GuardExPolicy(
    pii_enabled=True,
    pii_entities=["email", "phone_number"],
    pii_action="mask",
    pii_threshold=0.8,
    blocked_categories=["S1", "S3"]
)

# Production + EU + Healthcare context
ctx = GuardExContext(
    deployment=DeploymentContext.PRODUCTION,
    user=UserContext(region=Region.EU, industry=Industry.HEALTHCARE)
)

effective = resolve_policy(base, ctx)

# Result after composition:
# - pii_enabled: True (from PRODUCTION overlay)
# - pii_entities: ["email", "phone_number", "national_id", "tax_id", "iban", "medical_record_id", ...]
#   (UNION of base + EU region + HEALTHCARE industry)
# - pii_action: "block" (MAX_SEVERITY, EU and HEALTHCARE override base "mask")
# - pii_threshold: 0.4 (MIN of base 0.8, EU 0.5, HEALTHCARE 0.4)
# - blocked_categories: ["S1", "S3", ...] (UNION with any added categories)
```

## Resolution Layers

The resolver applies these layers on top of the base policy:

1. **Base policy** - Project's configuration
2. **Deployment profile** - DEVELOPMENT / STAGING / PRODUCTION / etc.
3. **Region profile** - US / EU / UK / CA / APAC / GLOBAL
4. **Industry profile** - HEALTHCARE / FINANCE / EDUCATION / etc.
5. **Auth status profile** - AUTHENTICATED / ANONYMOUS / SERVICE
6. **Request type profile** - CHAT / TOOL_CALL / RAG_RETRIEVAL / etc.
7. **Custom rules** - Project-specific PolicyOverride objects

Because every field composes with a semilattice join (OR / MIN / UNION / MAX_SEVERITY), the result is the same regardless of the order the layers are applied - there is no precedence between profiles, only accumulation of strictness.

## CachedPolicyResolver: Production Use

For production applications, use `CachedPolicyResolver` to avoid recomputing policies for identical contexts.

### Basic Usage

```python
from guardex.policy_resolver import CachedPolicyResolver
from guardex.policy import GuardExPolicy
from guardex.context import GuardExContext

base_policy = GuardExPolicy(...)

resolver = CachedPolicyResolver(base_policy, max_cache_size=256)

# First call: computes and caches
ctx1 = GuardExContext(user=UserContext(region=Region.EU))
policy1 = resolver.resolve(ctx1)  # CACHE MISS

# Second call with same context: instant cache hit
policy2 = resolver.resolve(ctx1)  # CACHE HIT

# Different context: new computation
ctx2 = GuardExContext(user=UserContext(region=Region.US))
policy3 = resolver.resolve(ctx2)  # CACHE MISS
```

### Monitoring Cache Performance

```python
# Check cache statistics
stats = resolver.stats
print(stats)
# {
#     "cache_size": 2,
#     "max_cache_size": 256,
#     "hits": 47,
#     "misses": 2,
#     "hit_rate": 95.9
# }

# Invalidate cache when base policy changes
resolver.invalidate()
```

### Bounded Cache

The cache is FIFO-bounded (default 256 entries) to prevent unbounded memory growth. When full, the oldest-inserted entry is evicted (insertion order, not access order):

```python
# Larger cache for high-variety contexts
resolver = CachedPolicyResolver(base_policy, max_cache_size=1024)
```

## Integration with Guard

Pass the context directly to `screen()` or `ascreen()`:

```python
from guardex import Guard, GuardExContext, UserContext, Region, Industry

guard = Guard()  # context resolution is in-process; server mode works too

ctx = GuardExContext(
    user=UserContext(region=Region.EU, industry=Industry.HEALTHCARE)
)

# Effective policy automatically adjusted for EU + Healthcare
result = guard.screen(user_input, gate="input", context=ctx)
```

The Guard internally uses `CachedPolicyResolver` to avoid redundant policy computation.

## Built-in Profiles: Full Reference

### Deployment Profiles

**DEVELOPMENT**
```python
PolicyOverride(
    fail_open=True,                 # Don't block on errors
    cascade_mode="speed",           # Fast feedback
    pii_threshold=0.9,              # Very lenient PII
    detailed_logging=True,          # See everything
    audit_logging=False,            # No audit burden
)
```

**STAGING**
```python
PolicyOverride(
    pii_enabled=True,
    block_on_unsafe_input=True,
    block_on_unsafe_output=True,
    cascade_mode="safety",          # Prefer accuracy
    audit_logging=True,
)
```

**PRODUCTION**
```python
PolicyOverride(
    pii_enabled=True,
    block_on_unsafe_input=True,
    block_on_unsafe_output=True,
    fail_open=False,                # Strict (block on error)
    cascade_mode="safety",
    audit_logging=True,
)
```

**DEMO**
```python
PolicyOverride(
    pii_enabled=True,
    block_on_unsafe_input=True,
    block_on_unsafe_output=True,
    pii_action="mask",              # Visible masking for demo
    cascade_mode="speed",           # Fast for sales
    detailed_logging=True,
)
```

**COMPLIANCE**
```python
PolicyOverride(
    pii_enabled=True,
    pii_entities_add=list(DEFAULT_PII_ENTITIES),
    pii_action="block",             # Never pass PII
    pii_threshold=0.3,              # Maximum sensitivity
    block_on_unsafe_input=True,
    block_on_unsafe_output=True,
    blocked_categories_add=list(ALL_CATEGORIES),  # Block everything unsafe
    fail_open=False,
    cascade_mode="safety",
    audit_logging=True,
    # detailed_logging is deliberately NOT set: compliance contexts must not
    # log plaintext user prompts - only hashed audit records.
)
```

### Region Profiles (EU Example)

```python
PolicyOverride(
    pii_entities_add=[
        "national_id",              # Passport, ID card
        "tax_id",                   # Tax authority ID
        "iban",                     # Bank account
        "eu_passport",
        "gdpr_special_category",    # Race, religion, health
    ],
    pii_action="block",             # GDPR: don't pass to LLM
    pii_threshold=0.5,              # More sensitive
    audit_logging=True,
)
```

### Industry Profiles (Healthcare Example)

```python
PolicyOverride(
    pii_entities_add=[
        "medical_record_number", "insurance_id",
        "diagnosis_code", "prescription", "patient_id",
        "health_plan_id", "medical_device_id",
    ],
    pii_action="block",             # HIPAA: never send to LLM
    pii_threshold=0.4,              # Very sensitive
    audit_logging=True,
)
```

## Advanced: Custom Context Rules

For project-specific policy composition, define custom `PolicyOverride` rules:

```python
from guardex.policy_override import PolicyOverride
from guardex.policy_resolver import CachedPolicyResolver
from guardex.context import GuardExContext

# Custom rule: tighten screening for a high-risk workflow
high_risk_rule = PolicyOverride(
    block_on_unsafe_input=True,
    block_on_unsafe_output=True,
    pii_threshold=0.4,        # MIN composition - lower than base wins
    pii_action="block",       # MAX_SEVERITY - block beats mask
    fail_open=False,          # AND composition - False wins
)

resolver = CachedPolicyResolver(
    base_policy,
    custom_rules=[high_risk_rule]
)

ctx = GuardExContext(...)
effective = resolver.resolve(ctx)
```

Composition is strictness-monotone: overrides can only tighten the effective policy, never loosen it. Loosening values are no-ops by design - `block_on_unsafe_input=False`, a `pii_threshold` higher than the current value, `fail_open=True`, or `pii_action="mask"` over a `"block"` base all leave the effective policy unchanged. To run with a more lenient policy, change the base `GuardExPolicy` itself.

## Serialization: HTTP Headers

In local mode, policy resolution happens in-process and needs no serialization.
When `Guard` points at a server (`base_url=`), the context is serialized into the
`X-GuardEx-Context` header so the server can resolve policy on its side:

```python
ctx = GuardExContext(user=UserContext(region=Region.EU))
header_value = ctx.to_header()
# Returns compact JSON string for X-GuardEx-Context header

# Server-side deserialization
ctx_restored = GuardExContext.from_header(header_value)
assert ctx_restored == ctx
```

!!! note "Forward Compatibility"
    Header deserialization gracefully falls back to defaults for unknown fields, allowing clients and servers of different versions to communicate safely.

## Common Patterns

### Multi-Tenant SaaS

```python
from guardex import Guard
from guardex.context import GuardExContext, UserContext, Region, Industry

def screen_user_input(user_id, tenant_id, user_input):
    guard = Guard()

    # Look up tenant config
    tenant = db.fetch_tenant(tenant_id)

    ctx = GuardExContext(
        user=UserContext(
            region=tenant.region,
            industry=tenant.industry,
            trust_score=user.trust_score,
        ),
        metadata={"tenant_id": tenant_id, "user_id": user_id}
    )

    return guard.screen(user_input, context=ctx)
```

### Role-Based Context

```python
from guardex.context import UserRole

if user.role == "admin":
    ctx = GuardExContext(user=UserContext(role=UserRole.ADMIN))
else:
    ctx = GuardExContext(user=UserContext(role=UserRole.USER))

result = guard.screen(user_input, context=ctx)
```

Note: `trust_score` does not drive policy resolution - it only contributes to the context's cache key. Setting `trust_score=1.0` does not loosen screening (composition can only tighten).

### Geo-Specific Compliance

```python
# Automatically choose region based on user's IP
user_region = geoip.lookup(request.remote_addr)

ctx = GuardExContext(
    deployment=DeploymentContext.PRODUCTION,
    user=UserContext(region=user_region),
)

result = guard.screen(user_input, context=ctx)
```

!!! info "Learn More"
    See [Guard SDK Reference](../sdk/guard.md) and [GuardExPolicy Reference](../sdk/policy.md) for complete parameter documentation.
