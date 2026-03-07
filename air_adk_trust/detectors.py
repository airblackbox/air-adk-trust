"""
air-adk-trust — Detection Utilities

PII scanning and prompt injection detection helpers.
Used by the AIRBlackboxPlugin callbacks.
"""

from __future__ import annotations

from .config import INJECTION_PATTERNS, PII_PATTERNS


def scan_pii(text: str) -> list[dict[str, str]]:
    """Scan text for PII patterns. Returns list of {type, match} dicts."""
    if not text:
        return []
    findings: list[dict[str, str]] = []
    for pii_type, pattern in PII_PATTERNS:
        for match in pattern.finditer(text):
            findings.append({"type": pii_type, "match": match.group()})
    return findings


def scan_injection(text: str) -> dict:
    """
    Scan text for prompt injection patterns.

    Returns:
        {
            "detected": bool,
            "score": float (0.0 - 1.0),
            "patterns": [{"name": str, "weight": float}, ...]
        }
    """
    if not text:
        return {"detected": False, "score": 0.0, "patterns": []}

    matched: list[dict[str, float]] = []
    for name, pattern, weight in INJECTION_PATTERNS:
        if pattern.search(text):
            matched.append({"name": name, "weight": weight})

    if not matched:
        return {"detected": False, "score": 0.0, "patterns": []}

    # Score = max weight among matched patterns
    score = max(m["weight"] for m in matched)
    return {"detected": True, "score": round(score, 2), "patterns": matched}


def redact_pii(text: str) -> str:
    """Replace PII matches with redaction tokens."""
    if not text:
        return text
    result = text
    for pii_type, pattern in PII_PATTERNS:
        result = pattern.sub(f"[REDACTED_{pii_type.upper()}]", result)
    return result
