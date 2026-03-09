"""
air-adk-trust — AIR Blackbox Trust Layer for Google ADK

EU AI Act compliance for Google Agent Development Kit agents.
Drop-in plugin with tamper-evident audit logging, PII detection,
prompt injection scanning, and tool policy enforcement.

Usage:
    from air_adk_trust import AIRBlackboxPlugin
    plugin = AIRBlackboxPlugin()
    agent = Agent(name="my_agent", ..., plugins=[plugin])
"""

from .audit_chain import AuditChain, AuditEntry, ChainVerification
from .config import AIRConfig, AuditConfig, RiskLevel
from .detectors import redact_pii, scan_injection, scan_pii
from .gate_client import GateClient
from .plugin import AIRBlackboxPlugin, classify_tool_risk

__all__ = [
    "AIRBlackboxPlugin",
    "AIRConfig",
    "AuditConfig",
    "AuditChain",
    "AuditEntry",
    "ChainVerification",
    "GateClient",
    "RiskLevel",
    "classify_tool_risk",
    "scan_pii",
    "scan_injection",
    "redact_pii",
]

__version__ = "0.2.0"
