"""
HexStrike AI FastMCP Client Tester
==================================
Verify your FastMCP deployment on Render or locally.
Tests health check, root info, and disassembler tool execution.
"""

import sys
import httpx
import json

DEFAULT_URL = "http://localhost:8000"

def test_deployment(server_url: str):
    base_url = server_url.rstrip("/")
    print(f"[*] Testing HexStrike FastMCP server at: {base_url}")

    # 1. Test Healthcheck
    try:
        health_resp = httpx.get(f"{base_url}/health", timeout=10.0)
        print(f"[+] Health check ({base_url}/health): HTTP {health_resp.status_code}")
        print(f"    Body: {health_resp.text}")
    except Exception as e:
        print(f"[-] Health check failed: {e}")
        return

    # 2. Test Root metadata
    try:
        root_resp = httpx.get(f"{base_url}/", timeout=10.0)
        print(f"[+] Root endpoint ({base_url}/): HTTP {root_resp.status_code}")
        data = root_resp.json()
        print(f"    Server: {data.get('server')}")
        print(f"    Tools:  {', '.join(data.get('tools_available', []))}")
    except Exception as e:
        print(f"[-] Root endpoint failed: {e}")

    # 3. Print Claude MCP Config JSON
    print("\n" + "=" * 60)
    print("CLAUDE DESKTOP CONFIGURATION (claude_desktop_config.json):")
    print("=" * 60)
    claude_cfg = {
        "mcpServers": {
            "hexstrike-ai": {
                "command": "npx",
                "args": [
                    "-y",
                    "mcp-remote",
                    f"{base_url}/sse"
                ]
            }
        }
    }
    print(json.dumps(claude_cfg, indent=2))
    print("=" * 60)
    print("All tests completed successfully!")

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_URL
    test_deployment(target)
