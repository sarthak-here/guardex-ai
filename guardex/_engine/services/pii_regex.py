# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 GuardEx
"""Regex-based PII detection.

Implements layers 1, 2, 4, 5 of the cascade:
    1. deny list (exact match)
    2. regex + checksum
    4. context-keyword boost
    5. allow list

Layer 3 (GLiNER NER) lives in gliner_provider.py.
"""

from __future__ import annotations

import re
import logging
from typing import Any

logger = logging.getLogger(__name__)


# Entity groups for UI display.
PII_CATEGORIES: dict[str, dict[str, Any]] = {
    "personal_info": {
        "display_name": "Personal Information",
        "entities": [
            "email", "phone_number", "name", "address", "ssn",
            "national_id", "passport_number", "date_of_birth", "driver_license",
        ],
    },
    "credentials": {
        "display_name": "Credentials & Secrets",
        "entities": [
            "password", "user_name", "private_key", "jwt_token",
            "auth_header", "secret",
        ],
    },
    "api_keys_tokens": {
        "display_name": "API Keys & Tokens",
        "entities": [
            "api_key", "aws_key", "github_token", "slack_token",
            "stripe_key", "google_api_key", "openai_key", "twilio_sid",
        ],
    },
    "financial": {
        "display_name": "Financial",
        "entities": ["credit_card", "bank_account", "iban"],
    },
    "network": {
        "display_name": "Network & Infrastructure",
        "entities": [
            "ip_address", "ipv6_address", "mac_address", "hostname",
            "database_url",
        ],
    },
}


def _c(pattern: str, flags: int = 0) -> re.Pattern[str]:
    return re.compile(pattern, flags)


REGEX_PATTERNS: dict[str, re.Pattern[str]] = {
    # Personal Info
    "email": _c(
        r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b"
    ),
    "phone_number": _c(
        r"(?<!\d)"
        r"(?:\+?1[\s.\-]?)?"
        r"(?:\(?\d{3}\)?[\s.\-]?)"
        r"\d{3}[\s.\-]?\d{4}"
        r"(?!\d)"
    ),
    "ssn": _c(
        r"\b\d{3}[\s.\-]?\d{2}[\s.\-]?\d{4}\b"
    ),
    "date_of_birth": _c(
        r"\b(?:"
        r"\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4}"  # MM/DD/YYYY, DD-MM-YYYY
        r"|"
        r"\d{4}[/\-]\d{1,2}[/\-]\d{1,2}"    # YYYY-MM-DD (ISO)
        r")\b"
    ),
    "national_id": _c(
        r"\b(?:"
        r"\d{4}\s?\d{4}\s?\d{4}"              # Aadhaar (India) 12-digit
        r"|"
        r"[A-Z]{5}\d{4}[A-Z]"                # PAN (India)
        r")\b"
    ),

    # Credentials
    "private_key": _c(
        r"-----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY-----"
    ),
    "jwt_token": _c(
        r"\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b"
    ),
    "auth_header": _c(
        r"\b(?:Bearer|Basic|Token)\s+[A-Za-z0-9_\-\.=+/]{20,}\b",
        re.IGNORECASE,
    ),

    # API Keys & Tokens
    "aws_key": _c(
        r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"
    ),
    "github_token": _c(
        r"\b(?:ghp|gho|ghs|ghr|github_pat)_[A-Za-z0-9_]{36,255}\b"
    ),
    "slack_token": _c(
        r"\bxox[bpas]\-[A-Za-z0-9\-]{10,}\b"
    ),
    "stripe_key": _c(
        r"\b[sr]k_(?:live|test)_[A-Za-z0-9]{20,}\b"
    ),
    "google_api_key": _c(
        r"\bAIzaSy[A-Za-z0-9_\-]{33}\b"
    ),
    "openai_key": _c(
        r"\bsk\-[A-Za-z0-9]{20,}\b"
    ),
    "twilio_sid": _c(
        r"\bAC[a-f0-9]{32}\b"
    ),

    # Financial
    "credit_card": _c(
        r"\b(?:"
        r"4\d{3}|5[1-5]\d{2}|6(?:011|5\d{2})|3[47]\d{2}|3(?:0[0-5]|[68]\d)\d"
        r")[\s\-]?(?:\d[\s\-]?){8,15}\d\b"
    ),
    "iban": _c(
        r"\b[A-Z]{2}\d{2}\s?[A-Z0-9]{4}[\s]?(?:[A-Z0-9]{4}[\s]?){1,7}[A-Z0-9]{1,4}\b"
    ),

    # Network
    "ip_address": _c(
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
    ),
    "ipv6_address": _c(
        r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"
        r"|"
        r"\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b"
        r"|"
        r"\b::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}\b"
    ),
    "mac_address": _c(
        r"\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b"
        r"|"
        r"\b(?:[0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4}\b"
    ),
    "database_url": _c(
        r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|sqlite)"
        r"://[^\s\"'<>]{10,}\b"
    ),
}


def luhn_check(number: str) -> bool:
    """Validate a number string using the Luhn algorithm (ISO/IEC 7812-1).

    Used for: credit cards, Canadian SIN, IMEI.
    """
    digits = [int(d) for d in number if d.isdigit()]
    if len(digits) < 13:
        return False
    odd_digits = digits[-1::-2]
    even_digits = digits[-2::-2]
    total = sum(odd_digits)
    total += sum(sum(divmod(d * 2, 10)) for d in even_digits)
    return total % 10 == 0


def iban_mod97_check(iban: str) -> bool:
    """Validate an IBAN using MOD-97 check (ISO 13616)."""
    cleaned = iban.replace(" ", "").upper()
    if len(cleaned) < 5 or not cleaned[:2].isalpha() or not cleaned[2:4].isdigit():
        return False
    rearranged = cleaned[4:] + cleaned[:4]
    numeric = ""
    for ch in rearranged:
        if ch.isdigit():
            numeric += ch
        elif ch.isalpha():
            numeric += str(ord(ch) - 55)
        else:
            return False
    try:
        return int(numeric) % 97 == 1
    except ValueError:
        return False


def ssn_structural_check(ssn: str) -> bool:
    """Validate US SSN structural rules (not a checksum, but eliminates known-invalid).

    Rules:
    - Area (first 3): not 000, 666, or 900-999
    - Group (middle 2): not 00
    - Serial (last 4): not 0000
    """
    digits = "".join(d for d in ssn if d.isdigit())
    if len(digits) != 9:
        return False
    area, group, serial = int(digits[:3]), int(digits[3:5]), int(digits[5:])
    if area == 0 or area == 666 or area >= 900:
        return False
    if group == 0:
        return False
    if serial == 0:
        return False
    return True


_CHECKSUM_VALIDATORS: dict[str, Any] = {
    "credit_card": luhn_check,
    "iban": iban_mod97_check,
    "ssn": ssn_structural_check,
}


# Patterns that match generic digit shapes (any 9-digit run looks like an
# SSN, any date looks like a DOB). These score below the default detection
# thresholds (0.7 runner / 0.85 policy) until a context keyword nearby
# boosts them - context gates the finding rather than merely strengthening
# it. Structurally distinctive patterns (API keys, IBAN, email) stay at
# the high base score.
_AMBIGUOUS_LABELS = frozenset({"ssn", "date_of_birth", "phone_number", "national_id"})
_AMBIGUOUS_BASE_SCORE = 0.6
_BASE_SCORE = 0.85


# Per-entity hotwords. Match within a window of a regex hit boosts the score.
CONTEXT_KEYWORDS: dict[str, list[str]] = {
    # Personal Info
    "email": ["email", "e-mail", "contact", "reply", "from:", "to:", "cc:", "bcc:", "mailto"],
    "phone_number": ["phone", "tel", "mobile", "cell", "fax", "call", "contact", "whatsapp", "sms", "dial"],
    "ssn": ["ssn", "social security", "tax id", "taxpayer", "itin", "ein", "national id", "tin"],
    "name": ["name", "full name", "first name", "last name", "mr.", "mrs.", "ms.", "dr."],
    "address": ["address", "street", "city", "state", "zip", "postal", "suite", "apt", "residence"],
    "date_of_birth": ["born", "birthday", "dob", "date of birth", "birth date", "age", "birth"],
    "national_id": ["national id", "aadhaar", "pan", "identity", "citizen", "id number", "nric"],
    "passport_number": ["passport", "travel document", "passport number", "passport no"],
    "driver_license": ["license", "driver", "driving", "dl", "licence", "permit"],

    # Credentials
    "password": ["password", "passwd", "pwd", "secret", "credentials", "pass", "passphrase"],
    "user_name": ["username", "user name", "login", "userid", "user id", "account", "handle"],
    "private_key": ["private key", "rsa", "ssh", "pem", "key file", "signing key"],
    "jwt_token": ["jwt", "token", "bearer", "authorization", "auth", "session"],
    "auth_header": ["authorization", "bearer", "basic auth", "token", "credentials", "header"],
    "secret": ["secret", "confidential", "sensitive", "classified", "private"],

    # API Keys & Tokens
    "api_key": ["api key", "apikey", "api_key", "key", "token", "secret", "auth"],
    "aws_key": ["aws", "amazon", "access key", "iam", "s3", "ec2", "credentials"],
    "github_token": ["github", "git", "token", "pat", "personal access", "repository"],
    "slack_token": ["slack", "bot token", "workspace", "channel"],
    "stripe_key": ["stripe", "payment", "billing", "checkout", "publishable", "secret key"],
    "google_api_key": ["google", "gcp", "api key", "maps", "youtube", "firebase"],
    "openai_key": ["openai", "gpt", "chatgpt", "api key", "model", "completion"],
    "twilio_sid": ["twilio", "sms", "sid", "account", "messaging"],

    # Financial
    "credit_card": ["card", "credit", "visa", "mastercard", "amex", "payment", "billing", "cvv", "expiry", "debit"],
    "bank_account": ["bank", "account", "routing", "aba", "swift", "wire", "deposit", "checking", "savings"],
    "iban": ["iban", "bank", "account", "transfer", "swift", "bic", "sepa", "international"],

    # Network
    "ip_address": ["ip", "address", "host", "server", "network", "subnet", "gateway", "proxy"],
    "ipv6_address": ["ipv6", "address", "host", "server", "network"],
    "mac_address": ["mac", "hardware", "ethernet", "network interface", "nic", "physical address"],
    "hostname": ["host", "server", "domain", "fqdn", "dns", "endpoint"],
    "database_url": ["database", "db", "connection string", "dsn", "postgres", "mysql", "mongo", "redis"],
}

_CONTEXT_PATTERNS: dict[str, re.Pattern[str]] = {}
for _label, _keywords in CONTEXT_KEYWORDS.items():
    _escaped = [re.escape(kw) for kw in _keywords]
    _CONTEXT_PATTERNS[_label] = re.compile(
        r"\b(?:" + "|".join(_escaped) + r")\b",
        re.IGNORECASE,
    )


def regex_detect(
    text: str,
    labels: list[str],
    extra_patterns: dict[str, re.Pattern[str]] | None = None,
) -> list[dict[str, Any]]:
    """Run regex-based PII detection on *text* for the given *labels*.

    Parameters
    ----------
    text : str
        Input text to scan.
    labels : list[str]
        Entity types to detect (only those with regex patterns are used).
    extra_patterns : dict, optional
        Additional regex patterns (e.g., from custom user-defined labels).

    Returns
    -------
    list of dicts, each with: text, label, score, start, end, method
    """
    results: list[dict[str, Any]] = []
    all_patterns = dict(REGEX_PATTERNS)
    if extra_patterns:
        all_patterns.update(extra_patterns)

    for label in labels:
        pattern = all_patterns.get(label)
        if pattern is None:
            continue

        for match in pattern.finditer(text):
            matched_text = match.group(0).strip()
            if not matched_text:
                continue

            # Run checksum validation if available for this entity type
            validator = _CHECKSUM_VALIDATORS.get(label)
            if validator and not validator(matched_text):
                # Credit cards with invalid Luhn: still emit at reduced score
                # so context enhancement (Layer 4) can boost if keywords like
                # "card", "credit", "visa" are nearby.
                if label == "credit_card":
                    results.append({
                        "text": matched_text,
                        "label": label,
                        "score": 0.5,
                        "start": match.start(),
                        "end": match.end(),
                        "method": "regex_weak",
                    })
                continue

            results.append({
                "text": matched_text,
                "label": label,
                "score": (
                    _AMBIGUOUS_BASE_SCORE if label in _AMBIGUOUS_LABELS
                    else _BASE_SCORE
                ),
                "start": match.start(),
                "end": match.end(),
                "method": "regex",
            })

    return results


def deny_list_detect(
    text: str,
    deny_list: set[str] | None,
) -> list[dict[str, Any]]:
    """Force-detect exact strings from the deny list. Score = 1.0."""
    if not deny_list:
        return []

    results: list[dict[str, Any]] = []
    text_lower = text.lower()

    for term in deny_list:
        term_lower = term.lower()
        start = 0
        while True:
            idx = text_lower.find(term_lower, start)
            if idx == -1:
                break
            results.append({
                "text": text[idx:idx + len(term)],
                "label": "deny_list",
                "score": 1.0,
                "start": idx,
                "end": idx + len(term),
                "method": "deny_list",
            })
            start = idx + 1

    return results


def context_enhance(
    text: str,
    entities: list[dict[str, Any]],
    window: int = 100,
    boost: float = 0.25,
    extra_patterns: dict | None = None,
) -> list[dict[str, Any]]:
    """Boost entity scores when context keywords appear nearby.

    Scans a window of *window* characters before and 50 after each detected
    entity for label-specific hotwords, excluding the entity span itself so a
    phrase cannot corroborate its own label (e.g. "Savings Account" must not
    boost via its own words). If a hotword is found, the score is boosted by
    *boost* (capped at 1.0).
    """
    text_lower = text.lower()
    enhanced: list[dict[str, Any]] = []

    for ent in entities:
        label = ent["label"]
        pattern = _CONTEXT_PATTERNS.get(label)
        # Check extra_patterns (project-scoped custom keywords) if no global match
        if pattern is None and extra_patterns:
            pattern = extra_patterns.get(label)

        if pattern is None:
            enhanced.append(ent)
            continue

        # Context = window before + window after the entity, NOT the span itself.
        ctx_start = max(0, ent["start"] - window)
        ctx_end = min(len(text), ent["end"] + 50)
        context_window = text_lower[ctx_start:ent["start"]] + " " + text_lower[ent["end"]:ctx_end]

        new_ent = dict(ent)
        if pattern.search(context_window):
            new_ent["score"] = min(1.0, ent["score"] + boost)
            new_ent["context_boost"] = True
        else:
            new_ent["context_boost"] = False

        enhanced.append(new_ent)

    return enhanced


def allow_list_filter(
    entities: list[dict[str, Any]],
    allow_list: set[str] | None,
) -> list[dict[str, Any]]:
    """Remove findings whose matched text appears in the allow list."""
    if not allow_list:
        return entities

    allow_lower = {v.lower() for v in allow_list}
    return [e for e in entities if e["text"].lower() not in allow_lower]


def _spans_overlap(a: dict[str, Any], b: dict[str, Any], threshold: float = 0.5) -> bool:
    """Check if two entity spans overlap by more than *threshold* fraction."""
    overlap_start = max(a["start"], b["start"])
    overlap_end = min(a["end"], b["end"])
    overlap_len = max(0, overlap_end - overlap_start)

    shorter = min(a["end"] - a["start"], b["end"] - b["start"])
    if shorter == 0:
        return False

    return overlap_len / shorter > threshold


def merge_detections(
    primary: list[dict[str, Any]],
    secondary: list[dict[str, Any]],
    corroboration_bonus: float = 0.05,
) -> list[dict[str, Any]]:
    """Merge detections from multiple layers, deduplicating overlapping spans.

    *primary* results (regex/deny_list) are preferred over *secondary* (NER).
    When both layers detect the same span, a small corroboration bonus is added.

    Parameters
    ----------
    primary : list
        Higher-confidence results (regex, deny list).
    secondary : list
        Lower-confidence results (GLiNER NER).
    corroboration_bonus : float
        Score boost when both layers agree (default 0.05).

    Returns
    -------
    Merged, deduplicated list sorted by start position.
    """
    # Copy primary dicts - the corroboration boost below must not mutate
    # the caller's entities through aliasing.
    merged: list[dict[str, Any]] = [dict(p) for p in primary]
    used_primary = merged

    for sec_ent in secondary:
        is_duplicate = False
        for pri_ent in used_primary:
            if _spans_overlap(sec_ent, pri_ent):
                # Corroboration: both layers agree - boost the primary score
                pri_ent["score"] = min(1.0, pri_ent["score"] + corroboration_bonus)
                pri_ent["corroborated"] = True
                is_duplicate = True
                break

        if not is_duplicate:
            ent = dict(sec_ent)
            if "method" not in ent:
                ent["method"] = "gliner"
            merged.append(ent)

    # Remove duplicate spans, keeping the highest score regardless of
    # which span starts first.
    final: list[dict[str, Any]] = []
    for ent in merged:
        is_dup = False
        for i, existing in enumerate(final):
            if _spans_overlap(ent, existing):
                is_dup = True
                if ent["score"] > existing["score"]:
                    final[i] = ent
                break
        if not is_dup:
            final.append(ent)

    final.sort(key=lambda e: (e["start"], -e["score"]))
    return final
