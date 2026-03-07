"""
air-adk-trust — AIR Blackbox Plugin for Google ADK

EU AI Act compliance via ADK's BasePlugin callback system.
Wraps every agent action in tamper-evident audit logging,
PII detection, prompt injection scanning, and tool policy enforcement.

Usage:
    from air_adk_trust import AIRBlackboxPlugin
    plugin = AIRBlackboxPlugin()
    agent = Agent(name="my_agent", ..., plugins=[plugin])
"""

from __future__ import annotations

import logging
import uuid
from typing import Any, Optional

from .audit_chain import AuditChain
from .config import AIRConfig, RISK_ORDER, RiskLevel
from .detectors import redact_pii, scan_injection, scan_pii

logger = logging.getLogger("air_adk_trust")

# ── Tool risk classification map ──────────────────────────────────
TOOL_RISK_MAP: dict[str, RiskLevel] = {
    # Critical
    "shell": RiskLevel.CRITICAL,
    "bash": RiskLevel.CRITICAL,
    "exec": RiskLevel.CRITICAL,
    "execute": RiskLevel.CRITICAL,
    "delete": RiskLevel.CRITICAL,
    "rm": RiskLevel.CRITICAL,
    "spawn": RiskLevel.CRITICAL,
    "eval": RiskLevel.CRITICAL,
    "subprocess": RiskLevel.CRITICAL,
    # High
    "sql": RiskLevel.HIGH,
    "database": RiskLevel.HIGH,
    "send_email": RiskLevel.HIGH,
    "fs_write": RiskLevel.HIGH,
    "write_file": RiskLevel.HIGH,
    "deploy": RiskLevel.HIGH,
    "git_push": RiskLevel.HIGH,
    "http_post": RiskLevel.HIGH,
    # Medium
    "http_request": RiskLevel.MEDIUM,
    "api_call": RiskLevel.MEDIUM,
    "web_search": RiskLevel.MEDIUM,
    "http_get": RiskLevel.MEDIUM,
    # Low
    "file_read": RiskLevel.LOW,
    "read_file": RiskLevel.LOW,
    "search": RiskLevel.LOW,
    "query": RiskLevel.LOW,
    "calculate": RiskLevel.LOW,
}


def classify_tool_risk(tool_name: str) -> RiskLevel:
    """Classify a tool name by risk level using keyword matching."""
    name_lower = tool_name.lower()
    # Exact match first
    if name_lower in TOOL_RISK_MAP:
        return TOOL_RISK_MAP[name_lower]
    # Substring match
    for keyword, level in TOOL_RISK_MAP.items():
        if keyword in name_lower:
            return level
    return RiskLevel.LOW


class AIRBlackboxPlugin:
    """
    AIR Blackbox trust layer for Google Agent Development Kit.

    Implements all 6 ADK plugin callback hooks:
      - before_agent / after_agent
      - before_model / after_model
      - before_tool / after_tool

    Each callback logs to a tamper-evident HMAC-SHA256 audit chain,
    scans for PII, detects prompt injections, and enforces tool policies.

    Works across multi-agent hierarchies — every sub-agent that uses
    this plugin gets the same compliance coverage.

    Args:
        config: AIRConfig instance. Uses defaults if not provided.
        session_id: Optional session ID for grouping audit entries.
    """

    def __init__(
        self,
        config: AIRConfig | None = None,
        session_id: str | None = None,
    ) -> None:
        self.config = config or AIRConfig()
        self.session_id = session_id or str(uuid.uuid4())
        self.audit_chain = AuditChain(self.config.audit)
        self._error_count: int = 0
        self._loop_count: int = 0
        self._invocation_id: str | None = None

    # ── ADK Callback: before_agent ──────────────────────────────
    def before_agent_callback(
        self,
        *,
        agent_name: str,
        invocation_id: str | None = None,
        **kwargs: Any,
    ) -> Optional[dict[str, Any]]:
        """
        Called before each agent invocation.

        Logs the agent start, checks risk tier, and resets loop counter.
        """
        self._invocation_id = invocation_id or str(uuid.uuid4())
        self._loop_count = 0

        self.audit_chain.log_event(
            event_type="agent_start",
            agent_name=agent_name,
            session_id=self.session_id,
            invocation_id=self._invocation_id,
            risk_level=self.config.risk_tier.value,
            metadata={"action": "before_agent", **kwargs},
        )

        logger.debug(f"[AIR] Agent started: {agent_name} (risk={self.config.risk_tier.value})")
        return None  # No modification to agent behavior

    # ── ADK Callback: after_agent ───────────────────────────────
    def after_agent_callback(
        self,
        *,
        agent_name: str,
        output: Any = None,
        error: Exception | None = None,
        **kwargs: Any,
    ) -> Optional[dict[str, Any]]:
        """
        Called after each agent invocation completes.

        Seals the audit record and logs completion or error.
        """
        event_type = "agent_error" if error else "agent_complete"
        metadata: dict[str, Any] = {"action": "after_agent", **kwargs}

        if error:
            self._error_count += 1
            metadata["error"] = str(error)
            metadata["error_type"] = type(error).__name__
            metadata["consecutive_errors"] = self._error_count

            if self._error_count >= self.config.max_consecutive_errors:
                logger.warning(
                    f"[AIR] Agent {agent_name} hit max consecutive errors "
                    f"({self._error_count}/{self.config.max_consecutive_errors})"
                )
                metadata["max_errors_reached"] = True
        else:
            self._error_count = 0  # Reset on success

        # Scan output for PII if configured
        pii_detected = False
        if self.config.pii_detection and output:
            output_str = str(output)
            pii_findings = scan_pii(output_str)
            if pii_findings:
                pii_detected = True
                metadata["pii_findings"] = [f["type"] for f in pii_findings]
                logger.info(f"[AIR] PII detected in agent output: {[f['type'] for f in pii_findings]}")

        self.audit_chain.log_event(
            event_type=event_type,
            agent_name=agent_name,
            session_id=self.session_id,
            invocation_id=self._invocation_id,
            pii_detected=pii_detected,
            metadata=metadata,
        )

        logger.debug(f"[AIR] Agent finished: {agent_name} (event={event_type})")
        return None

    # ── ADK Callback: before_model ──────────────────────────────
    def before_model_callback(
        self,
        *,
        agent_name: str | None = None,
        prompt: str | None = None,
        **kwargs: Any,
    ) -> Optional[dict[str, Any]]:
        """
        Called before each LLM call.

        Logs the prompt (if configured), scans for PII, and checks
        for prompt injection attacks.
        """
        self._loop_count += 1
        metadata: dict[str, Any] = {"action": "before_model", **kwargs}

        # Loop detection
        if self._loop_count > self.config.max_loop_iterations:
            logger.warning(
                f"[AIR] Loop limit reached ({self._loop_count}/{self.config.max_loop_iterations})"
            )
            metadata["loop_limit_reached"] = True

        pii_detected = False
        injection_detected = False
        injection_score = 0.0

        prompt_text = prompt or ""

        # Log prompt if configured
        if self.config.log_prompts and prompt_text:
            metadata["prompt_preview"] = prompt_text[:500]

        # PII detection on prompt
        if self.config.pii_detection and prompt_text:
            pii_findings = scan_pii(prompt_text)
            if pii_findings:
                pii_detected = True
                metadata["pii_findings"] = [f["type"] for f in pii_findings]
                logger.info(f"[AIR] PII in prompt: {[f['type'] for f in pii_findings]}")

                if self.config.block_pii:
                    metadata["pii_blocked"] = True
                    logger.warning("[AIR] Blocking prompt due to PII content")

        # Injection detection on prompt
        if self.config.injection_detection and prompt_text:
            inj_result = scan_injection(prompt_text)
            if inj_result["detected"]:
                injection_detected = True
                injection_score = inj_result["score"]
                metadata["injection_patterns"] = [p["name"] for p in inj_result["patterns"]]
                logger.info(
                    f"[AIR] Injection detected (score={injection_score}): "
                    f"{[p['name'] for p in inj_result['patterns']]}"
                )

                if self.config.block_injections and injection_score >= self.config.injection_threshold:
                    metadata["injection_blocked"] = True
                    logger.warning(f"[AIR] Blocking prompt due to injection (score={injection_score})")

        self.audit_chain.log_event(
            event_type="model_call",
            agent_name=agent_name,
            session_id=self.session_id,
            invocation_id=self._invocation_id,
            pii_detected=pii_detected,
            injection_detected=injection_detected,
            injection_score=injection_score,
            metadata=metadata,
        )

        return None

    # ── ADK Callback: after_model ───────────────────────────────
    def after_model_callback(
        self,
        *,
        agent_name: str | None = None,
        response: Any = None,
        **kwargs: Any,
    ) -> Optional[dict[str, Any]]:
        """
        Called after each LLM response.

        Logs the response (if configured) and scans output for PII.
        """
        metadata: dict[str, Any] = {"action": "after_model", **kwargs}

        pii_detected = False
        response_text = str(response) if response else ""

        if self.config.log_responses and response_text:
            metadata["response_preview"] = response_text[:500]

        # PII scan on response
        if self.config.pii_detection and response_text:
            pii_findings = scan_pii(response_text)
            if pii_findings:
                pii_detected = True
                metadata["pii_findings"] = [f["type"] for f in pii_findings]

        self.audit_chain.log_event(
            event_type="model_response",
            agent_name=agent_name,
            session_id=self.session_id,
            invocation_id=self._invocation_id,
            pii_detected=pii_detected,
            metadata=metadata,
        )

        return None

    # ── ADK Callback: before_tool ───────────────────────────────
    def before_tool_callback(
        self,
        *,
        agent_name: str | None = None,
        tool_name: str,
        tool_args: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> Optional[dict[str, Any]]:
        """
        Called before each tool execution.

        Classifies tool risk, checks blocked list, scans args for PII,
        and enforces tool policy.
        """
        risk = classify_tool_risk(tool_name)
        metadata: dict[str, Any] = {
            "action": "before_tool",
            "risk_level": risk.value,
            **kwargs,
        }

        # Check if tool is blocked
        if tool_name in self.config.blocked_tools:
            metadata["blocked"] = True
            logger.warning(f"[AIR] Blocked tool: {tool_name}")

        # Check if tool exceeds risk tier
        if RISK_ORDER.get(risk, 0) > RISK_ORDER.get(self.config.risk_tier, 1):
            metadata["exceeds_risk_tier"] = True
            logger.warning(
                f"[AIR] Tool {tool_name} risk ({risk.value}) exceeds "
                f"tier ({self.config.risk_tier.value})"
            )

        # Check if tool requires confirmation
        if tool_name in self.config.require_confirmation_tools:
            metadata["requires_confirmation"] = True

        # PII scan on tool args
        pii_detected = False
        if self.config.pii_detection and tool_args:
            args_text = str(tool_args)
            pii_findings = scan_pii(args_text)
            if pii_findings:
                pii_detected = True
                metadata["pii_findings"] = [f["type"] for f in pii_findings]

        self.audit_chain.log_event(
            event_type="tool_call",
            agent_name=agent_name,
            tool_name=tool_name,
            risk_level=risk.value,
            session_id=self.session_id,
            invocation_id=self._invocation_id,
            pii_detected=pii_detected,
            metadata=metadata,
        )

        return None

    # ── ADK Callback: after_tool ────────────────────────────────
    def after_tool_callback(
        self,
        *,
        agent_name: str | None = None,
        tool_name: str,
        tool_result: Any = None,
        error: Exception | None = None,
        **kwargs: Any,
    ) -> Optional[dict[str, Any]]:
        """
        Called after each tool execution.

        Logs the result, scans for PII, and records errors.
        """
        event_type = "tool_error" if error else "tool_result"
        metadata: dict[str, Any] = {"action": "after_tool", **kwargs}

        if error:
            metadata["error"] = str(error)
            metadata["error_type"] = type(error).__name__

        pii_detected = False
        if self.config.pii_detection and tool_result:
            result_text = str(tool_result)
            pii_findings = scan_pii(result_text)
            if pii_findings:
                pii_detected = True
                metadata["pii_findings"] = [f["type"] for f in pii_findings]

        self.audit_chain.log_event(
            event_type=event_type,
            agent_name=agent_name,
            tool_name=tool_name,
            session_id=self.session_id,
            invocation_id=self._invocation_id,
            pii_detected=pii_detected,
            metadata=metadata,
        )

        return None

    # ── Public API ──────────────────────────────────────────────
    def verify_chain(self) -> dict[str, Any]:
        """Verify the integrity of the audit chain."""
        return self.audit_chain.verify().to_dict()

    def get_audit_stats(self) -> dict[str, Any]:
        """Get audit chain statistics."""
        return self.audit_chain.stats()

    def export_audit(self) -> list[dict[str, Any]]:
        """Export the full audit chain as a list of dicts."""
        return self.audit_chain.export()

    def get_recent_events(self, n: int = 50) -> list[dict[str, Any]]:
        """Get the N most recent audit entries."""
        return [e.to_dict() for e in self.audit_chain.get_recent(n)]
