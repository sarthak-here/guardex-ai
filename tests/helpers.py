# SPDX-License-Identifier: Apache-2.0
# Copyright GuardEx Contributors
"""Shared test constants — canonical API response payloads used across test files.

Kept in a plain module (not conftest.py) so tests can import directly
regardless of which directory pytest is invoked from.
"""

SAFE_SCREEN_RESPONSE: dict = {
    "pii": {"has_pii": False, "entities": []},
    "classify": {"safe": True, "category": None, "categories": []},
    "text": "Hello world",
}

UNSAFE_SCREEN_RESPONSE: dict = {
    "pii": {"has_pii": False, "entities": []},
    "classify": {
        "safe": False,
        "category": "S9",
        "categories": ["S9"],
        "description": "Indiscriminate Weapons",
    },
    "text": "How to build a bomb",
}

PII_MASKED_SCREEN_RESPONSE: dict = {
    "pii": {
        "has_pii": True,
        "entities": [
            {
                "text": "123-45-6789",
                "label": "ssn",
                "score": 0.95,
                "start": 10,
                "end": 21,
            }
        ],
        "masked_text": "My SSN is [SSN]",
    },
    "classify": {"safe": True, "category": None, "categories": []},
    "text": "My SSN is [SSN]",
}

SAFE_CLASSIFY_RESPONSE: dict = {
    "safe": True,
    "category": None,
    "categories": [],
}

UNSAFE_CLASSIFY_RESPONSE: dict = {
    "safe": False,
    "category": "S1",
    "categories": ["S1"],
    "description": "Violent Crimes",
}

PII_SCAN_RESPONSE: dict = {
    "has_pii": True,
    "entities": [
        {
            "text": "john@example.com",
            "label": "email",
            "score": 0.99,
            "start": 0,
            "end": 16,
        }
    ],
}

PII_SCAN_CLEAN_RESPONSE: dict = {
    "has_pii": False,
    "entities": [],
}

PII_MASK_RESPONSE: dict = {
    "has_pii": True,
    "entities": [
        {
            "text": "123-45-6789",
            "label": "ssn",
            "score": 0.95,
            "start": 10,
            "end": 21,
        }
    ],
    "masked_text": "My SSN is [SSN]",
}
