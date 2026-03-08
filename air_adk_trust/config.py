"""
air-adk-trust — Configuration

Defines risk levels, PII patterns, and plugin configuration
for the AIR Blackbox ADK trust layer.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


RISK_ORDER = {
    RiskLevel.LOW: 0,
    RiskLevel.MEDIUM: 1,
    RiskLevel.HIGH: 2,
    RiskLevel.CRITICAL: 3,
}


# --- PII Detection Patterns ---

PII_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("email", re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")),
    ("phone_us", re.compile(r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b")),
    ("ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("credit_card", re.compile(r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b")),
    ("ip_address", re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")),
]

# --- Prompt Injection Patterns ---

INJECTION_PATTERNS: list[tuple[str, re.Pattern, float]] = [
    ("role_override", re.compile(r"you are now|act as|pretend to be|ignore previous", re.I), 0.8),
    ("system_prompt_leak", re.compile(r"show.*system.*prompt|reveal.*instructions|print.*system", re.I), 0.7),
    ("jailbreak", re.compile(r"DAN|do anything now|bypass|override safety", re.I), 0.9),
    ("instruction_ignore", re.compile(r"ignore all|disregard|forget.*instructions", re.I), 0.85),
    ("privilege_escalation", re.compile(r"admin mode|developer mode|sudo|root access", re.I), 0.75),
    ("data_exfil", re.compile(r"send.*to.*url|post.*to.*endpoint|curl.*http", re.I), 0.7),
    ("encoding_attack", re.compile(r"base64|rot13|hex.*encode|decode.*this", re.I), 0.5),
]


@dataclass
class AuditConfig:
    """Configuration for the audit ledger."""

    local_path: str = ".air/audit_chain.json"
    max_entries: int = 10000
    forward_to_gateway: bool = False
    gateway_url: str | None = None
    gateway_key: str | None = None
    hmac_secret: str | None = None


@dataclass
class AIRConfig:
    """Main configuration for the AIR Blackbox ADK plugin."""

    # Risk management
    risk_tier: RiskLevel = RiskLevel.MEDIUM

    # Data governance
    pii_detection: bool = True
    block_pii: bool = False  # Log-only by default, set True to block

    # Tool policy
    blocked_tools: list[str] = field(default_factory=list)
    require_confirmation_tools: list[str] = field(default_factory=list)

    # Prompt injection
    injection_detection: bool = True
    block_injections: bool = False  # Log-only by default
    injection_threshold: float = 0.7

    # Robustness
    max_consecutive_errors: int = 5
    max_loop_iterations: int = 50

    # Audit
    audit: AuditConfig = field(default_factory=AuditConfig)

    # General
    log_prompts: bool = False  # Set True to log full prompt text (privacy consideration)
    log_responses: bool = False

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AIRConfig:
        audit_data = data.pop("audit", {})
        audit = AuditConfig(**audit_data) if audit_data else AuditConfig()
        risk = data.pop("risk_tier", "medium")
        return cls(
            audit=audit,
            risk_tier=RiskLevel(risk),
            **{k: v for k, v in data.items() if k in cls.__dataclass_fields__},
        )
