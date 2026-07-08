"""Tests for guardex.pii_vault — PIIVault reversible tokenisation."""

import pytest
from guardex.pii_vault import PIIVault, VaultEntry, _TOKEN_RE
from guardex._types import PIIResult, PIIEntity


def _make_pii_result(entities_data: list[dict]) -> PIIResult:
    """Helper to construct PIIResult from simplified dicts."""
    entities = [
        PIIEntity(
            text=e["text"],
            label=e["label"],
            score=e.get("score", 0.95),
            start=e["start"],
            end=e["end"],
        )
        for e in entities_data
    ]
    return PIIResult(has_pii=bool(entities), entities=entities)


class TestPIIVault:

    def test_vault_and_restore_single_entity(self):
        vault = PIIVault()
        text = "Email john@example.com please"
        pii = _make_pii_result([
            {"text": "john@example.com", "label": "email", "start": 6, "end": 22},
        ])

        vaulted, v = vault.vault_text(text, pii)

        # Original text should be replaced
        assert "john@example.com" not in vaulted
        assert "{{pii:email:" in vaulted
        assert v is vault  # same instance returned

        # Restore should recover original
        restored = vault.restore(vaulted)
        assert restored == text

    def test_vault_multiple_entities(self):
        vault = PIIVault()
        text = "Name: John, SSN: 123-45-6789"
        pii = _make_pii_result([
            {"text": "John", "label": "name", "start": 6, "end": 10},
            {"text": "123-45-6789", "label": "ssn", "start": 17, "end": 28},
        ])

        vaulted, _ = vault.vault_text(text, pii)

        assert "John" not in vaulted
        assert "123-45-6789" not in vaulted
        assert "{{pii:name:" in vaulted
        assert "{{pii:ssn:" in vaulted
        assert len(vault) == 2

        restored = vault.restore(vaulted)
        assert restored == text

    def test_vault_empty_entities(self):
        vault = PIIVault()
        pii = PIIResult(has_pii=False, entities=[])
        vaulted, _ = vault.vault_text("no pii here", pii)
        assert vaulted == "no pii here"
        assert len(vault) == 0

    def test_dedup_same_value(self):
        vault = PIIVault()
        text = "Email: a@b.com and a@b.com"
        pii = _make_pii_result([
            {"text": "a@b.com", "label": "email", "start": 7, "end": 14},
            {"text": "a@b.com", "label": "email", "start": 19, "end": 26},
        ])

        vaulted, _ = vault.vault_text(text, pii)
        # Should use same token for same value — only 1 entry
        assert len(vault) == 1
        restored = vault.restore(vaulted)
        assert restored == text

    def test_restore_preserves_unknown_tokens(self):
        vault = PIIVault()
        # A token that isn't in this vault should be left as-is
        fake_token = "{{pii:email:00000000000000000000000000000000}}"
        result = vault.restore(f"Hello {fake_token}")
        assert fake_token in result

    def test_get_original(self):
        vault = PIIVault()
        pii = _make_pii_result([
            {"text": "secret@mail.com", "label": "email", "start": 0, "end": 15},
        ])
        vaulted, _ = vault.vault_text("secret@mail.com", pii)

        # Extract token from vaulted text
        match = _TOKEN_RE.search(vaulted)
        assert match is not None
        token = match.group(0)

        assert vault.get_original(token) == "secret@mail.com"
        assert vault.get_original("{{pii:email:nonexistent_token_here}}") is None

    def test_entries(self):
        vault = PIIVault()
        pii = _make_pii_result([
            {"text": "test@x.com", "label": "email", "start": 0, "end": 10},
        ])
        vault.vault_text("test@x.com", pii)

        entries = vault.entries()
        assert len(entries) == 1
        assert isinstance(entries[0], VaultEntry)
        assert entries[0].label == "email"
        assert entries[0].original == "test@x.com"

    def test_clear(self):
        vault = PIIVault()
        pii = _make_pii_result([
            {"text": "data", "label": "name", "start": 0, "end": 4},
        ])
        vault.vault_text("data", pii)
        assert len(vault) == 1
        vault.clear()
        assert len(vault) == 0

    def test_max_entries_raises(self):
        vault = PIIVault(max_entries=2)
        for i in range(2):
            pii = _make_pii_result([
                {"text": f"user{i}@x.com", "label": "email", "start": 0, "end": 12},
            ])
            vault.vault_text(f"user{i}@x.com", pii)

        # Third entry should raise
        pii = _make_pii_result([
            {"text": "user2@x.com", "label": "email", "start": 0, "end": 11},
        ])
        with pytest.raises(RuntimeError, match="PIIVault is full"):
            vault.vault_text("user2@x.com", pii)

    def test_token_entropy_128_bits(self):
        """Verify tokens use 128-bit entropy (32 hex chars)."""
        vault = PIIVault()
        pii = _make_pii_result([
            {"text": "test@x.com", "label": "email", "start": 0, "end": 10},
        ])
        vaulted, _ = vault.vault_text("test@x.com", pii)

        match = _TOKEN_RE.search(vaulted)
        assert match is not None
        hex_part = match.group(2)
        assert len(hex_part) == 32  # 32 hex chars = 128 bits

    def test_repr(self):
        vault = PIIVault(max_entries=500)
        assert "PIIVault" in repr(vault)
        assert "500" in repr(vault)

    def test_restore_in_llm_response(self):
        """End-to-end: vault text, simulate LLM using token, restore."""
        vault = PIIVault()
        user_text = "My email is alice@corp.com"
        pii = _make_pii_result([
            {"text": "alice@corp.com", "label": "email", "start": 12, "end": 26},
        ])

        vaulted, _ = vault.vault_text(user_text, pii)

        # Simulate LLM referencing the token in its response
        token = _TOKEN_RE.search(vaulted).group(0)
        llm_response = f"I'll send the confirmation to {token}"

        restored = vault.restore(llm_response)
        assert restored == "I'll send the confirmation to alice@corp.com"
