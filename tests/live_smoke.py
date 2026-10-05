"""Call every tool of the installed `nodemaven-mcp` over stdio against the live API.

Needs NODEMAVEN_APIKEY in the environment. Prints results without secrets, and
fails if the account's proxy password appears in any tool result.
Run: python tests/live_smoke.py
"""

import asyncio
import json
import os
import shutil
import sys

from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from nodemaven import Client

CALLS = (
    ("account_status", {}),
    ("list_locations", {"kind": "countries", "limit": 3}),
    ("proxy_url", {"country": "us", "session_id": "smoke1", "ttl": "10m"}),
    ("check_proxy", {"country": "us"}),
    ("check_proxy", {"country": "us", "session_id": "smoke1", "ttl": "10m"}),
    ("traffic_stats", {}),
    ("top_domains", {"limit": 3}),
    ("list_sub_users", {}),
)


async def main() -> int:
    if not os.environ.get("NODEMAVEN_APIKEY"):
        print("set NODEMAVEN_APIKEY first")
        return 2
    password = Client().me()["proxy_password"]
    params = StdioServerParameters(command=shutil.which("nodemaven-mcp"), env=dict(os.environ))
    leaks = 0
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            for name, args in CALLS:
                result = await session.call_tool(name, args)
                payload = result.structured_content or [c.text for c in result.content]
                text = json.dumps(payload)
                if password and password in text:
                    leaks += 1
                    print(f"{name}: LEAK - result contains the proxy password")
                    continue
                if name == "list_sub_users" and not result.is_error:
                    text = f"{len(payload.get('rows', []))} sub-users"
                print(f"{name} {args}: error={result.is_error} {text[:300]}")
    print("LEAKS:", leaks)
    return 1 if leaks else 0


sys.exit(asyncio.run(main()))
