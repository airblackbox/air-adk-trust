"""
Gate Client — Connects trust layers to the AIR Blackbox Gate server.

When a Gate URL is configured, tool calls are forwarded to the Gate API
for centralized policy enforcement, Slack approvals, and audit storage.

Without a Gate URL, the trust layer works fully standalone with local
audit chains — zero dependency on external services.

Usage:
    client = GateClient(gateway_url="http://localhost:8000")
    decision = client.submit_action(
        agent_id="my-agent",
        action_type="email",
        tool_name="send_email",
        payload={"to": "jane@example.com"},
    )
    # decision = {"decision": "auto_allowed", "event_id": "...", ...}
"""

from __future__ import annotations

import json
import logging
import urllib.request
import urllib.error
from typing import Any, Optional

logger = logging.getLogger("air_trust.gate_client")


class GateClient:
    """Thin HTTP client for the AIR Blackbox Gate API."""

    def __init__(
        self,
        gateway_url: str | None = None,
        gateway_key: str | None = None,
        timeout: float = 10.0,
    ) -> None:
        self.gateway_url = gateway_url.rstrip("/") if gateway_url else None
        self.gateway_key = gateway_key
        self.timeout = timeout
        self._available: bool | None = None

    @property
    def is_configured(self) -> bool:
        """True if a gateway URL is set."""
        return bool(self.gateway_url)

    def submit_action(
        self,
        *,
        agent_id: str,
        action_type: str,
        tool_name: str,
        payload: dict[str, Any] | None = None,
        input_context: str = "",
    ) -> dict[str, Any] | None:
        """
        Submit an action to the Gate for policy evaluation.

        Returns the Gate response (decision, event_id, rule_name, reason)
        or None if Gate is unavailable or not configured.
        """
        if not self.gateway_url:
            return None

        body = {
            "agent_id": agent_id,
            "action_type": action_type,
            "tool_name": tool_name,
            "payload": payload or {},
            "input_context": input_context,
        }

        return self._post("/actions", body)

    def approve_action(
        self,
        event_id: str,
        authorized_by: str,
        comment: str = "",
    ) -> dict[str, Any] | None:
        """Approve a pending action on the Gate."""
        if not self.gateway_url:
            return None

        return self._post(
            f"/actions/{event_id}/approve",
            {"authorized_by": authorized_by, "comment": comment},
        )

    def reject_action(
        self,
        event_id: str,
        authorized_by: str,
        comment: str = "",
    ) -> dict[str, Any] | None:
        """Reject a pending action on the Gate."""
        if not self.gateway_url:
            return None

        return self._post(
            f"/actions/{event_id}/reject",
            {"authorized_by": authorized_by, "comment": comment},
        )

    def health_check(self) -> dict[str, Any] | None:
        """Check if the Gate server is healthy."""
        if not self.gateway_url:
            return None
        return self._get("/health")

    def verify_chain(self) -> dict[str, Any] | None:
        """Verify the Gate's audit chain."""
        if not self.gateway_url:
            return None
        return self._get("/verify")

    # ── HTTP helpers ─────────────────────────────────────────────

    def _post(self, path: str, body: dict) -> dict[str, Any] | None:
        """POST JSON to the Gate API."""
        try:
            url = f"{self.gateway_url}{path}"
            data = json.dumps(body).encode("utf-8")
            headers = {"Content-Type": "application/json"}
            if self.gateway_key:
                headers["Authorization"] = f"Bearer {self.gateway_key}"

            req = urllib.request.Request(url, data=data, headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))

        except urllib.error.HTTPError as e:
            body_text = e.read().decode("utf-8", errors="replace")[:200]
            logger.warning(f"Gate API error {e.code}: {body_text}")
            return None
        except Exception as e:
            logger.debug(f"Gate unavailable ({path}): {e}")
            return None

    def _get(self, path: str) -> dict[str, Any] | None:
        """GET from the Gate API."""
        try:
            url = f"{self.gateway_url}{path}"
            headers = {}
            if self.gateway_key:
                headers["Authorization"] = f"Bearer {self.gateway_key}"

            req = urllib.request.Request(url, headers=headers, method="GET")
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))

        except Exception as e:
            logger.debug(f"Gate unavailable ({path}): {e}")
            return None
