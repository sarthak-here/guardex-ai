# PII Vault and De-masking

The PII Vault solves a fundamental tension in guardrail design: **blocking PII from reaching the LLM breaks workflows that need the actual values in responses**.

## The Problem

```python
# User's input with PII
user_message = "Please send a reminder to john@example.com and call 555-1234"

# Traditional masking
masked = "[EMAIL] and call [PHONE_NUMBER]"

# LLM responses with masked tokens cannot help the user
response = "I sent a reminder to [EMAIL]"  # Email is lost!
```

The LLM can't reference actual values if it only sees tokens. But sending real PII to the LLM violates compliance requirements (GDPR, HIPAA).

## The Solution: Reversible Tokenization

PIIVault stores a per-session mapping of random tokens to original PII values:

```python
from guardex.pii_vault import PIIVault
from guardex import Guard

vault = PIIVault()
guard = Guard()

# Step 1: Screen and vault the user input
user_message = "Please send a reminder to john@example.com"

pii_result = guard.pii_scan(user_message)
vaulted_text, vault = vault.vault_text(user_message, pii_result)

# vaulted_text: "Please send a reminder to {{pii:email:a3f9b2c1d8e0f5a9c2e1d0f9a8b7c6e5}}"
# The token is cryptographically secure, not the original email

# Step 2: Send vaulted text to LLM
response = llm.invoke(vaulted_text)
# LLM: "I'll send a reminder to {{pii:email:a3f9b2c1d8e0f5a9c2e1d0f9a8b7c6e5}}"

# Step 3: Restore original values before showing to user
final_response = vault.restore(response)
# final_response: "I'll send a reminder to john@example.com"
```

The LLM sees only tokens, never the real PII, but its responses can still
reference the actual values because `restore()` swaps them back before the
user sees the reply. Tokens carry 128-bit entropy. Works with any LLM.

## Workflow: Three Phases

### Phase 1: Scan and Vault

```python
from guardex import Guard
from guardex.pii_vault import PIIVault

vault = PIIVault()
guard = Guard()

# PII detection
pii_result = guard.pii_scan(user_input)

# Replace PII with tokens
vaulted_text, vault = vault.vault_text(user_input, pii_result)
```

### Phase 2: LLM Processing

```python
# Send only vaulted text to LLM
# No network call at this point
llm_response = llm.invoke(vaulted_text, conversation_history=vaulted_history)
```

### Phase 3: De-masking

```python
# Restore original values in response
final_response = vault.restore(llm_response)

# Show to user
print(final_response)
```

## Token Format

```
{{pii:<LABEL>:<32-HEX-CHARS>}}

Example:
{{pii:email:a3f9b2c1d8e0f5a9c2e1d0f9a8b7c6e5}}
```

| Component | Meaning | Example |
|-----------|---------|---------|
| `pii:` | Token prefix | Literal |
| `<LABEL>` | Entity type (lowercase) | `email`, `phone_number`, `ssn` |
| `<32-HEX>` | 128-bit secure random | `a3f9b2c1d8e0f5a9c2e1d0f9a8b7c6e5` |

### Token Security

Tokens use 128-bit entropy (32 hex characters), generated with
`secrets.token_hex(16)`. The token space is 2^128, so collisions are
negligible at any realistic vault size; `vault_text()` also deduplicates
identical values, so the same PII string always maps to one token.

```python
import secrets

token_hex = secrets.token_hex(16)  # 16 bytes = 128 bits = 32 hex chars
token = f"{{{{pii:email:{token_hex}}}}}"
print(token)
# {{pii:email:a3f9b2c1d8e0f5a9c2e1d0f9a8b7c6e5}}
```

## PIIVault Class

### Basic Interface

```python
from guardex.pii_vault import PIIVault

# Create a vault for this session
vault = PIIVault(max_entries=1_000)

# Vault a text and get vaulted version
vaulted_text, vault = vault.vault_text(original_text, pii_result)

# Restore original values in LLM response
final_text = vault.restore(llm_response)

# Clean up when session ends
vault.clear()
```

### vault_text() Method

```python
def vault_text(
    text: str,
    pii_result  # PIIResult from guard.pii_scan() or guard.screen()
) -> Tuple[str, PIIVault]:
    """Replace PII spans in text with vault tokens.

    Processes entities in reverse span order so that earlier offsets
    remain valid as we substitute later ones first.

    Returns:
        (vaulted_text, self) - returns same vault for chaining
    """
```

**Example:**

```python
from guardex import Guard
from guardex.pii_vault import PIIVault

guard = Guard()
vault = PIIVault()

text = "Contact john@example.com or call 555-1234"

# Scan for PII
pii_result = guard.pii_scan(text)
# pii_result.entities: [
#   PIIEntity(text="john@example.com", label="email", score=0.97, start=8, end=24),
#   PIIEntity(text="555-1234", label="phone_number", score=0.92, start=33, end=41),
# ]

# Vault the text
vaulted, vault = vault.vault_text(text, pii_result)

# vaulted: "Contact {{pii:email:a3f9...}} or call {{pii:phone_number:b2e1...}}"

# Chaining support
vaulted2, same_vault = vault.vault_text(another_text, another_pii)
assert same_vault is vault  # Same object returned
```

### restore() Method

```python
def restore(self, text: str) -> str:
    """Replace all vault tokens in text with their original values.

    Tokens not found in this vault are left unchanged (safe for
    multi-vault or partial text scenarios).

    Returns:
        Text with tokens replaced by original PII values
    """
```

**Example:**

```python
llm_response = "I've sent an email to {{pii:email:a3f9...}} with details"

final_response = vault.restore(llm_response)
# final_response: "I've sent an email to john@example.com with details"
```

### Additional Methods

```python
# Get original value for a token
original = vault.get_original("{{pii:email:a3f9...}}")
# Returns: "john@example.com"

# List all stored entries (for audit)
entries = vault.entries()
# Returns: [VaultEntry(...), VaultEntry(...), ...]

# Check vault size
count = len(vault)
# Returns: 2

# Clear vault when session ends
vault.clear()

# String representation
print(vault)
# "PIIVault(entries=2, max=1000)"
```

## VaultEntry: Stored Mapping

Each PII value stored in the vault has a corresponding `VaultEntry`:

```python
@dataclass
class VaultEntry:
    token: str        # Full token string, e.g., "{{pii:email:a3f9...}}"
    label: str        # Entity type, e.g., "email"
    original: str     # The real PII value
```

**Accessing entries:**

```python
vault = PIIVault()
vaulted_text, vault = vault.vault_text(text, pii_result)

# Iterate over stored entries
for entry in vault.entries():
    print(f"{entry.label}: {entry.token} -> {entry.original}")
    # email: {{pii:email:a3f9...}} -> john@example.com
    # phone_number: {{pii:phone_number:b2e1...}} -> 555-1234
```

## Deduplication

Vaults automatically deduplicate identical PII values:

```python
from guardex import PIIEntity, PIIResult
from guardex.pii_vault import PIIVault

vault = PIIVault()

pii1 = PIIResult(has_pii=True, entities=[
    PIIEntity(text="john@example.com", label="email", score=0.95, start=8, end=24),
])
pii2 = PIIResult(has_pii=True, entities=[
    PIIEntity(text="john@example.com", label="email", score=0.95, start=3, end=19),
])

vaulted1, vault = vault.vault_text("Contact john@example.com", pii1)
vaulted2, vault = vault.vault_text("Or john@example.com", pii2)

# Same token for same value
assert vaulted1.count("{{pii:email:") == vaulted2.count("{{pii:email:")

# Vault stores only one entry
assert len(vault) == 1
```

## Thread Safety

PIIVault is **not thread-safe by default**. For concurrent use:

```python
from threading import Lock
from guardex.pii_vault import PIIVault

# Option 1: One vault per request
def handle_request():
    vault = PIIVault()  # Fresh vault for this request
    # ... process ...
    vault.clear()

# Option 2: Shared vault with lock
vault = PIIVault()
vault_lock = Lock()

def concurrent_process(text, pii_result):
    with vault_lock:
        vaulted, _ = vault.vault_text(text, pii_result)
    # Process vaulted text
    with vault_lock:
        restored = vault.restore(response)
    return restored
```

!!! note "Recommendation"
    Create a **new `PIIVault` per session/request** rather than sharing across threads. This is simpler, faster, and safer.

## Safety Limits

### max_entries

Prevents unbounded growth in long-running processes:

```python
# Default: 1,000 entries
vault = PIIVault(max_entries=1_000)

# After max_entries is reached, raises RuntimeError
vaulted_text, vault = vault.vault_text(many_items, pii_result)
# RuntimeError: PIIVault is full (1000 entries).
# Call vault.clear() between sessions or increase max_entries.
```

**Choosing the right limit:**

| max_entries | Use Case |
|-------------|----------|
| 1,000 | Single request, strict memory limit |
| 10,000 | Multi-turn conversation (6-10 turns) |
| 100,000 | Long-running document processing |

## Complete Workflow Example

```python
from guardex import Guard
from guardex.pii_vault import PIIVault

class SecureConversation:
    def __init__(self):
        self.guard = Guard()
        self.llm = LLMClient()
        self.vault = PIIVault(max_entries=1_000)

    def chat_turn(self, user_message: str) -> str:
        # 1. Scan user input for PII
        pii_result = self.guard.pii_scan(user_message)

        # 2. Vault the PII
        vaulted_input, _ = self.vault.vault_text(user_message, pii_result)

        # 3. Screen the vaulted text
        guard_result = self.guard.screen(vaulted_input, gate="input")
        if guard_result.blocked:
            return "I can't help with that."

        # 4. Send vaulted text to LLM (PII never exposed)
        llm_response = self.llm.invoke(vaulted_input)

        # 5. Restore original values in response
        final_response = self.vault.restore(llm_response)

        # 6. Screen the final response for safety
        output_result = self.guard.screen(final_response, gate="output")
        if output_result.blocked:
            return "I encountered an issue generating a response."

        return final_response

    def session_end(self):
        # Clean up vault
        self.vault.clear()
```

## Integration with Guard

Combine a vault with `Guard.pii_scan()` to tokenize any PII the Guard detects:

```python
from guardex import Guard
from guardex.pii_vault import PIIVault

guard = Guard()
vault = PIIVault()

# PII scan returns entities with span information
pii_result = guard.pii_scan(text)

# Vault automatically uses span info for precise replacement
vaulted_text, vault = vault.vault_text(text, pii_result)
```

## Output Masking vs. Input Vaulting

| Scenario | Use Case | Method |
|----------|----------|--------|
| **User input** | Need to vault before sending to LLM | `vault.vault_text()` |
| **LLM output** | Need to restore after LLM processes | `vault.restore()` |
| **Display to user** | Need actual values | Vaulted workflow |
| **Audit logs** | Need to mask for compliance | `guard.pii_scan()` + manual masking |

## Performance Considerations

### Processing Order

PIIVault processes entities in **reverse span order** to keep offsets valid:

```python
# Input with 2 PII values
text = "Contact john@example.com at 555-1234"
#                    ^start=8,end=27  ^start=36,end=44

# Processing reverse: 555-1234 first, then john@example.com
# This ensures offsets remain correct as we substitute from the end
```

**Performance:**
- Scanning: O(n) where n = entities count
- Restoration: O(m) where m = tokens in response (fast regex)
- Memory: O(e) where e = total PII values stored

### Payload Size Optimization

```python
# Tokens are ~60 bytes each
vault_token = "{{pii:email:a3f9b2c1d8e0f5a9c2e1d0f9a8b7c6e5}}"  # 47 bytes

# Shorter than most PII
email = "john.smith.senior.developer@company.com"  # 37 bytes

# For high-volume PII, vaulting may reduce payload size
```

## Best Practices

### Use Vaults in Multi-Turn Conversations

```python
def chat_session(user_id):
    guard = Guard()
    vault = PIIVault()  # One vault per session

    for turn_num in range(max_turns):
        user_message = input()

        # All turns use same vault
        pii = guard.pii_scan(user_message)
        vaulted, _ = vault.vault_text(user_message, pii)

        response = llm.invoke(vaulted)
        final = vault.restore(response)
        print(final)

    vault.clear()  # Clean up at session end
```

### Monitor Vault Growth

```python
vault = PIIVault(max_entries=10_000)
CAPACITY = 10_000

for turn in turns:
    vaulted, _ = vault.vault_text(text, pii_result)

    # Track vault size
    print(f"Vault: {len(vault)} / {CAPACITY} entries")

    if len(vault) > CAPACITY * 0.9:
        logger.warning("Vault approaching capacity")
```

### Audit Vault Contents

```python
vault = PIIVault()

# ... process requests ...

# Generate audit report
audit_report = {
    "timestamp": datetime.now(),
    "vault_size": len(vault),
    "entities_by_type": {},
}

for entry in vault.entries():
    if entry.label not in audit_report["entities_by_type"]:
        audit_report["entities_by_type"][entry.label] = 0
    audit_report["entities_by_type"][entry.label] += 1

print(audit_report)
# {
#   "timestamp": "2024-01-15T10:30:00Z",
#   "vault_size": 23,
#   "entities_by_type": {"email": 5, "phone_number": 3, "ssn": 15}
# }
```

!!! info "Learn More"
    - See [Guard SDK Reference](../sdk/guard.md) for `pii_scan()` and `pii_mask()` method signatures
    - See [PII Detection Guide](pii-detection.md) for entity types and configuration
    - See [Observability Guide](observability.md) for monitoring PII handling
