"""
Google ADK + AIR Blackbox Gate — Quickstart Example

Shows how to connect a Google ADK agent to the AIR Blackbox Gate
for centralized policy enforcement and audit trails.

Prerequisites:
    pip install air-adk-trust google-adk

Run the Gate first:
    pip install air-blackbox[server]
    uvicorn gate.proxy:app --reload

Then run this script:
    python examples/quickstart_with_gate.py
"""

from air_adk_trust import AIRBlackboxPlugin, AIRConfig, AuditConfig

# ── Configure with Gate URL ──────────────────────────────────────
config = AIRConfig(
    audit=AuditConfig(
        gateway_url="http://localhost:8000",  # Gate server
        # gateway_key="your-api-key",         # Optional auth
        forward_to_gateway=True,
    ),
    pii_detection=True,
    injection_detection=True,
)

plugin = AIRBlackboxPlugin(config=config)

# ── Use with Google ADK ──────────────────────────────────────────
# from google.adk import Agent
#
# agent = Agent(
#     name="recruiting-agent",
#     model="gemini-2.0-flash",
#     plugins=[plugin],
#     tools=[search_tool, email_tool, calendar_tool],
# )
# result = agent.run("Find ML engineers in the Bay Area")

# ── Standalone demo (no ADK needed) ─────────────────────────────
print("AIR Blackbox ADK Trust Layer v0.2.0")
print("=" * 50)

# Simulate agent lifecycle
print("\n1. Agent starting...")
plugin.before_agent_callback(agent_name="recruiting-agent")

# Simulate a search tool (low risk)
print("\n2. Tool call: web_search (low risk)...")
plugin.before_tool_callback(
    agent_name="recruiting-agent",
    tool_name="web_search",
    tool_args={"query": "ML engineers San Francisco"},
)
plugin.after_tool_callback(
    agent_name="recruiting-agent",
    tool_name="web_search",
    tool_result="Found 15 candidates",
)
print("   -> Search: logged")

# Simulate an email tool (high risk)
print("\n3. Tool call: send_email (high risk)...")
plugin.before_tool_callback(
    agent_name="recruiting-agent",
    tool_name="send_email",
    tool_args={"to": "jane@example.com", "subject": "Opportunity"},
)
plugin.after_tool_callback(
    agent_name="recruiting-agent",
    tool_name="send_email",
    tool_result="Email sent",
)
print("   -> Email: logged")

# Simulate a dangerous tool (critical risk)
print("\n4. Tool call: shell (critical risk)...")
plugin.before_tool_callback(
    agent_name="recruiting-agent",
    tool_name="shell",
    tool_args={"command": "rm -rf /"},
)
print("   -> Shell: logged (would be blocked by Gate policy)")

# Agent complete
print("\n5. Agent finishing...")
plugin.after_agent_callback(agent_name="recruiting-agent")

# Check audit stats
print("\n6. Audit stats:")
stats = plugin.get_audit_stats()
for k, v in stats.items():
    print(f"   {k}: {v}")

# Verify chain
print("\n7. Chain verification:")
chain = plugin.verify_chain()
print(f"   Valid: {chain['valid']}")
print(f"   Entries: {chain['total_entries']}")

# Check Gate connection
print("\n8. Gate connection:")
if plugin.gate.is_configured:
    health = plugin.gate.health_check()
    if health:
        print(f"   Connected to Gate: {health.get('status')}")
        print(f"   Gate events: {health.get('events_count')}")
    else:
        print("   Gate not reachable (running in local-only mode)")
else:
    print("   No Gate URL configured (local-only mode)")

print("\nDone! All actions logged with HMAC-SHA256 audit chain.")
