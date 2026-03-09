# Adding EU AI Act Compliance to Google ADK

**Package**: `air-adk-trust` v0.2.0
**Last updated**: March 2026

---

## Before You Start

- Python 3.9+
- A Google ADK project (`google-adk` installed)
- ~5 minutes to integrate
- Optional: AIR Blackbox Gate for centralized policy enforcement

## Step 1: Install

```bash
pip install air-adk-trust
```

## Step 2: Add the Trust Layer

The trust layer plugs in as a Google ADK plugin. One line to add:

**Before** (no compliance):
```python
from google.adk.agents import Agent

agent = Agent(
    name="my_agent",
    model="gemini-2.0-flash",
    instruction="You are a helpful assistant.",
    tools=[search_tool, email_tool],
)
```

**After** (EU AI Act compliant):
```python
from google.adk.agents import Agent
from air_adk_trust import AIRBlackboxPlugin

plugin = AIRBlackboxPlugin()

agent = Agent(
    name="my_agent",
    model="gemini-2.0-flash",
    instruction="You are a helpful assistant.",
    tools=[search_tool, email_tool],
    plugins=[plugin],  # ← add this
)
```

Every tool call is now logged in a tamper-evident audit chain with automatic PII detection, injection scanning, and risk classification.

## Step 3: Verify It's Working

After running your agent, check the audit chain:

```python
stats = plugin.get_audit_stats()
print(stats)
# {'total_events': 4, 'tool_calls': 3, 'blocked': 0, 'pii_detected': 1}

verification = plugin.verify_chain()
print(verification)
# ChainVerification(valid=True, total_entries=4, verified_entries=4, errors=[])
```

If `valid=True`, the chain has cryptographic integrity — no entries tampered with or missing.

## Step 4: Run a Compliance Scan

```bash
pip install air-compliance
air-compliance scan .
```

Expected output with the trust layer active:
```
AIR Blackbox Compliance Scanner v1.x

Scanning: ./my_adk_project

Article  9 — Risk Management:        PASS  (tool risk classification active)
Article 10 — Data Governance:         PASS  (PII detection enabled)
Article 11 — Technical Documentation: PASS  (audit chain exportable)
Article 12 — Record-Keeping:          PASS  (HMAC-SHA256 audit chain active)
Article 14 — Human Oversight:         PASS  (tool blocking configured)
Article 15 — Robustness:              PASS  (injection detection enabled)

Result: 6/6 technical checks passing
```

## What's Happening Under the Hood

When you add `AIRBlackboxPlugin`, these features activate automatically:

1. **Audit Chain** — Every tool call is logged with timestamps, agent ID, tool name, inputs/outputs, risk level, and an HMAC-SHA256 hash linking each entry to the previous one. Creates a tamper-evident chain for Article 12 (Record-Keeping).

2. **Tool Risk Classification** — Tools are auto-classified based on name patterns: `shell`/`exec`/`delete` → CRITICAL, `sql`/`send_email`/`deploy` → HIGH, `api_call`/`http_request` → MEDIUM, everything else → LOW. Supports Article 9 (Risk Management).

3. **PII Detection** — Inputs are scanned for emails, phone numbers, SSNs, credit card numbers, and IP addresses. Detected PII is flagged in the audit trail. Supports Article 10 (Data Governance).

4. **Injection Detection** — Prompts are scanned for injection patterns ("ignore previous instructions", encoded payloads, role hijacking). Suspicious inputs are flagged. Supports Article 15 (Robustness).

5. **Tool Blocking** — Tools above a configured risk threshold can be blocked automatically. The `before_tool_callback` returns metadata that ADK uses to skip execution. Supports Article 14 (Human Oversight).

## Connecting to AIR Blackbox Gate (Optional)

Gate is a centralized policy server for organization-wide tool policy enforcement.

```python
from air_adk_trust import AIRBlackboxPlugin, AIRConfig, AuditConfig

config = AIRConfig(
    audit=AuditConfig(
        gateway_url="http://localhost:8000",  # Gate server URL
        # gateway_key="your-api-key",         # Optional API key
    )
)

plugin = AIRBlackboxPlugin(config=config)
```

With Gate connected:
- Tool calls are checked against Gate's centralized policy before execution
- Gate can `auto_allow`, `require_approval`, or `block` based on org-wide rules
- All decisions are logged in Gate's audit trail alongside the local chain
- If Gate is unavailable, the plugin falls back to local policy (graceful degradation)

## Advanced Configuration

### Custom Tool Risk Levels

```python
from air_adk_trust import AIRConfig, RiskLevel

config = AIRConfig(
    custom_tool_risks={
        "google_search": RiskLevel.LOW,
        "read_document": RiskLevel.MEDIUM,
        "send_slack_message": RiskLevel.HIGH,
        "run_shell_command": RiskLevel.CRITICAL,
    }
)
plugin = AIRBlackboxPlugin(config=config)
```

### Blocked Tools

```python
config = AIRConfig(
    blocked_tools=["shell", "exec", "delete"],  # Always block these
    block_above=RiskLevel.HIGH,                  # Block HIGH + CRITICAL
)
plugin = AIRBlackboxPlugin(config=config)
```

### Export Audit Chain

```python
# Get the full audit chain as JSON (for regulatory submission)
chain_data = plugin.export_chain()

# Save to file
import json
with open("audit_chain.json", "w") as f:
    json.dump(chain_data, f, indent=2)
```

## API Reference

### `AIRBlackboxPlugin`

The main entry point. Inherits from Google ADK's `BasePlugin`.

| Method | Returns | Description |
|--------|---------|-------------|
| `get_audit_stats()` | `dict` | Event counts by type |
| `verify_chain()` | `ChainVerification` | Cryptographic integrity check |
| `export_chain()` | `list[dict]` | Full audit chain as JSON |
| `before_tool_callback(tool, args, ...)` | `dict` | Policy check before tool execution |
| `after_tool_callback(tool, args, result, ...)` | `None` | Log tool result to audit chain |

### `GateClient`

HTTP client for AIR Blackbox Gate. Initialized automatically when `gateway_url` is set.

| Method | Returns | Description |
|--------|---------|-------------|
| `submit_action(...)` | `dict \| None` | Submit tool call for policy decision |
| `approve_action(event_id, ...)` | `dict \| None` | Approve a pending action |
| `reject_action(event_id, ...)` | `dict \| None` | Reject a pending action |
| `health_check()` | `dict \| None` | Check Gate server status |
| `verify_chain()` | `dict \| None` | Verify Gate's audit chain |

### `classify_tool_risk(tool_name)`

Classifies a tool name into a risk level based on built-in patterns.

```python
from air_adk_trust import classify_tool_risk, RiskLevel

classify_tool_risk("google_search")  # RiskLevel.LOW
classify_tool_risk("send_email")     # RiskLevel.HIGH
classify_tool_risk("shell")          # RiskLevel.CRITICAL
```

### `AIRConfig`

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `blocked_tools` | `list[str]` | `[]` | Tool names to always block |
| `block_above` | `RiskLevel` | `CRITICAL` | Block tools at this level and above |
| `custom_tool_risks` | `dict` | `{}` | Override risk level per tool |
| `audit.gateway_url` | `str \| None` | `None` | Gate server URL |
| `audit.gateway_key` | `str \| None` | `None` | Gate API key |
| `audit.hmac_key` | `str \| None` | auto-generated | Key for audit chain signing |

## FAQ

**Q: Does this send my code to the cloud?**
No. Everything runs locally. Gate is optional and self-hosted.

**Q: Does this work with ADK's built-in tools?**
Yes. The plugin wraps all tools registered with the agent, including ADK's built-in Google Search, code execution, and custom function tools.

**Q: Is this legal compliance?**
No. AIR Blackbox checks *technical* requirements from the EU AI Act. It's a linter for AI governance. Always consult legal counsel for compliance certification.

**Q: What if Gate is down?**
The plugin falls back to local policy enforcement automatically. Zero downtime, zero errors.

**Q: Can I use multiple plugins?**
Yes. ADK supports plugin chaining. `AIRBlackboxPlugin` works alongside any other ADK plugins.

---

*Document version: 1.0 — Applies to air-adk-trust v0.2.0*
