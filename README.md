# air-adk-trust

**EU AI Act compliance for Google Agent Development Kit (ADK) agents.**

Drop-in plugin that adds tamper-evident audit logging, PII detection, prompt injection scanning, and tool policy enforcement to any ADK agent — including multi-agent hierarchies.

Part of the [AIR Blackbox](https://airblackbox.ai) trust layer ecosystem.

## Quickstart

```python
from air_adk_trust import AIRBlackboxPlugin
from google.adk import Agent

plugin = AIRBlackboxPlugin()
agent = Agent(name="my_agent", model="gemini-2.0-flash", plugins=[plugin])
```

That's it. Every agent action is now logged to a tamper-evident HMAC-SHA256 audit chain.

## Install

```bash
pip install air-adk-trust
```

## What It Does

The plugin hooks into all 6 ADK callback points:

| Callback | What AIR Does |
|---|---|
| `before_agent` | Start audit record, check risk tier |
| `after_agent` | Finalize record, seal HMAC chain |
| `before_model` | Log prompt, scan PII, detect injection |
| `after_model` | Log response, scan output for PII |
| `before_tool` | Classify tool risk, enforce policy, check blocked list |
| `after_tool` | Log result, scan for PII leakage |

## EU AI Act Coverage

| Article | Requirement | How AIR Covers It |
|---|---|---|
| Art. 9 | Risk Management | Tool risk classification + configurable risk tiers |
| Art. 10 | Data Governance | PII detection + optional blocking/redaction |
| Art. 11 | Technical Documentation | Structured JSON audit export |
| Art. 12 | Record Keeping | HMAC-SHA256 tamper-evident audit chain |
| Art. 14 | Human Oversight | Blocked tool lists + confirmation requirements |
| Art. 15 | Robustness | Prompt injection detection + loop limits + error tracking |

## Configuration

```python
from air_adk_trust import AIRBlackboxPlugin, AIRConfig, RiskLevel

config = AIRConfig(
    risk_tier=RiskLevel.HIGH,       # LOW, MEDIUM, HIGH, CRITICAL
    pii_detection=True,              # Scan for emails, SSNs, credit cards, etc.
    block_pii=False,                 # Set True to block prompts with PII
    injection_detection=True,        # Scan for prompt injection attacks
    block_injections=False,          # Set True to block detected injections
    blocked_tools=["shell", "exec"], # Forbidden tool names
    max_consecutive_errors=5,        # Error circuit breaker
    max_loop_iterations=50,          # Loop detection limit
)

plugin = AIRBlackboxPlugin(config=config)
```

## Verify the Audit Chain

```python
# Check chain integrity
result = plugin.verify_chain()
print(result)  # {"valid": True, "total_entries": 42}

# Export for compliance reporting
audit_data = plugin.export_audit()

# Get recent events
events = plugin.get_recent_events(n=10)
```

## Multi-Agent Support

ADK plugins fire for every sub-agent in a hierarchy. One plugin instance covers the entire agent tree:

```python
from air_adk_trust import AIRBlackboxPlugin
from google.adk import Agent

plugin = AIRBlackboxPlugin()

researcher = Agent(name="researcher", model="gemini-2.0-flash", plugins=[plugin])
writer = Agent(name="writer", model="gemini-2.0-flash", plugins=[plugin])
coordinator = Agent(
    name="coordinator",
    model="gemini-2.0-flash",
    sub_agents=[researcher, writer],
    plugins=[plugin],
)
```

## AIR Blackbox Ecosystem

| Package | Framework | PyPI |
|---|---|---|
| `air-langchain-trust` | LangChain | [![PyPI](https://img.shields.io/pypi/v/air-langchain-trust)](https://pypi.org/project/air-langchain-trust/) |
| `air-crewai-trust` | CrewAI | [![PyPI](https://img.shields.io/pypi/v/air-crewai-trust)](https://pypi.org/project/air-crewai-trust/) |
| `air-autogen-trust` | AutoGen | [![PyPI](https://img.shields.io/pypi/v/air-autogen-trust)](https://pypi.org/project/air-autogen-trust/) |
| `air-openai-trust` | OpenAI SDK | [![PyPI](https://img.shields.io/pypi/v/air-openai-trust)](https://pypi.org/project/air-openai-trust/) |
| **`air-adk-trust`** | **Google ADK** | **This package** |
| `air-blackbox-mcp` | MCP Server | [![PyPI](https://img.shields.io/pypi/v/air-blackbox-mcp)](https://pypi.org/project/air-blackbox-mcp/) |

## License

Apache 2.0
