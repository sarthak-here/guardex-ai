# SDK Reference: PIIVault

`guardex.PIIVault` - Reversible PII tokenization with de-masking. The LLM never sees real PII, but you can restore original values after generation.

!!! tip "When to use PIIVault vs. pii_action='mask'"
    Use `pii_action="mask"` when PII should be **permanently removed** (logging, analytics).
    Use `PIIVault` when the LLM must **reference PII in its response** and you need to restore it (customer support, email drafting, document summarization).

---

## Import

```python
from guardex import PIIVault, VaultEntry
```

---

## PIIVault

### Constructor

```python
PIIVault(max_entries: int = 1_000)
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `max_entries` | `int` | `1000` | Maximum stored tokens. Raises `RuntimeError` when full. Call `vault.clear()` between sessions. |

### Class Attributes

#### SYSTEM_PROMPT_HINT

```python
PIIVault.SYSTEM_PROMPT_HINT  # str
```

A ready-to-use system prompt snippet that teaches LLMs to use vault tokens naturally. **Always include this in your system message when sending vaulted text to an LLM.**

```python
messages = [
    {"role": "system", "content": f"You are a support agent. {PIIVault.SYSTEM_PROMPT_HINT}"},
    {"role": "user", "content": vaulted_text},
]
```

Without this hint, smaller models (GPT-4o-mini, open-source 7B) may ignore or refuse to use the tokens.

---

### vault_text(text, pii_result)

Replace PII spans with vault tokens. Processes entities in **reverse span order** so earlier offsets remain valid.

```python
vault_text(
    text: str,
    pii_result: PIIResult,
) -> tuple[str, PIIVault]
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `text` | `str` | Original text containing PII |
| `pii_result` | `PIIResult` | Result from `guard.pii_scan()` or `guard.screen().pii` |

**Returns:** `tuple[str, PIIVault]` - `(vaulted_text, self)`. Always unpack both values.

```python
vault = PIIVault()
pii_result = guard.pii_scan("Contact john@acme.com")
vaulted, vault = vault.vault_text("Contact john@acme.com", pii_result)
# vaulted = "Contact {{pii:email:a3f2b7c4e9d01234abcdef5678901234}}"
```

!!! warning "Always unpack the tuple"
    `vault_text()` returns a tuple. If you write `result = vault.vault_text(...)` without unpacking, you'll get a `(str, PIIVault)` tuple instead of a string.

---

### restore(text)

Replace all vault tokens in text with their original PII values. Tokens not found in this vault are left unchanged.

```python
restore(text: str) -> str
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `text` | `str` | Text containing vault tokens (typically an LLM response) |

**Returns:** `str` - Text with tokens replaced by original values.

```python
llm_response = "I'll email {{pii:email:a3f2b7c4e9d01234abcdef5678901234}} now."
final = vault.restore(llm_response)
# "I'll email john@acme.com now."
```

---

### get_original(token)

Look up the original PII value for a specific token.

```python
get_original(token: str) -> str | None
```

Returns `None` if the token is not in this vault.

---

### entries()

Return all stored vault entries (useful for audit logging).

```python
entries() -> list[VaultEntry]
```

```python
for entry in vault.entries():
    print(f"{entry.label}: {entry.token} -> {entry.original}")
```

---

### clear()

Wipe the vault. Call at session end to free memory and prevent cross-session leakage.

```python
vault.clear()
```

---

### len(vault)

Returns the number of stored tokens.

```python
print(len(vault))  # 3
```

---

## VaultEntry

```python
@dataclass
class VaultEntry:
    token: str      # "{{pii:email:a3f2...}}"
    label: str      # "email"
    original: str   # "john@acme.com"
```

---

## Token Format

Tokens follow the pattern: `{{pii:<label>:<32-hex-chars>}}`

- `label`: lowercase entity type (`email`, `name`, `ssn`, `phone_number`, `ipv6_address`, etc.)
- `hex`: 32 hex characters = 128 bits of entropy (`secrets.token_hex(16)`)
- Regex: `\{\{pii:([a-z0-9_]+):([0-9a-f]{32})\}\}`

---

## Complete Example

```python
from openai import OpenAI
from guardex import Guard, PIIVault

guard = Guard()
vault = PIIVault()
client = OpenAI()

# 1. Scan
user_text = "Hi, I'm Alice. Email me at alice@corp.com about order ORD-456."
pii_result = guard.pii_scan(user_text)

# 2. Vault
vaulted, vault = vault.vault_text(user_text, pii_result)

# 3. Send to LLM with SYSTEM_PROMPT_HINT
response = client.chat.completions.create(
    model="gpt-4o",
    messages=[
        {"role": "system", "content": f"You are customer support. {PIIVault.SYSTEM_PROMPT_HINT}"},
        {"role": "user", "content": vaulted},
    ],
)

# 4. Screen output for safety
safe_output = guard.screen_or_raise(response.choices[0].message.content, gate="output")

# 5. Restore
final = vault.restore(safe_output)
print(final)
# "Hi Alice, I'll send tracking info to alice@corp.com for order ORD-456."

vault.clear()
```

---

## Dedup Behavior

If the same PII value appears multiple times in the text, it gets the **same token**. This is correct - "john@acme.com" appearing 3 times maps to one token, and all 3 instances in the LLM response restore to the same email.

Different values with the same label get different tokens:
- `john@acme.com` → `{{pii:email:a3f2...}}`
- `bob@corp.com` → `{{pii:email:9c1d...}}`

---

## Thread Safety

PIIVault is **not thread-safe**. Create one vault per request in concurrent applications:

```python
async def handle_request(user_text: str):
    vault = PIIVault()  # one per request
    # ... vault, send to LLM, restore ...
```
