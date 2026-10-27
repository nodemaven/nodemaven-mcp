"""Call every tool of the installed `nodemaven-mcp` over stdio against the live API.

Needs NODEMAVEN_APIKEY in the environment. Prints results without secrets, and
fails if the account's proxy password appears in any tool result. With
NODEMAVEN_MCP_ALLOW_WRITE=1 it also creates a sub-user and a whitelisted IP
(SMOKE_WHITELIST_IP, default 192.0.2.10), changes them and deletes them.
Run: python tests/live_smoke.py
"""

import asyncio
import json
import os
import shutil
import sys
import time

from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from nodemaven import Client

CALLS = (
    ("account_status", {}),
    ("list_locations", {"kind": "countries", "limit": 3}),
    ("list_locations", {"kind": "regions", "country_code": "us", "limit": 100}),
    ("list_locations", {"kind": "regions", "country_code": "us", "limit": 100, "offset": 100}),
    ("proxy_url", {"country": "us", "session_id": "smoke1", "ttl": "10m"}),
    ("check_proxy", {"country": "us"}),
    ("check_proxy", {"country": "us", "session_id": "smoke1", "ttl": "10m"}),
    ("traffic_stats", {}),
    ("top_domains", {"limit": 3}),
    ("list_sub_users", {}),
    ("list_sub_users", {"page": 2}),
    ("list_whitelist_ips", {}),
    ("test_proxy_on_site", {"url": "https://example.com", "country": "us"}),
    ("test_proxy_on_site", {"url": "https://example.com", "country": "de",
                            "session_id": "smoke1", "ttl": "10m"}),
)


def write_calls(results: dict) -> list:
    """The write cycle, built step by step from earlier results."""
    name = f"smoke_delete_me_{int(time.time())}"
    ip = os.environ.get("SMOKE_WHITELIST_IP", "192.0.2.10")
    return [
        ("create_sub_user", lambda: {"username": name, "traffic_limit": 1000}),
        ("update_sub_user", lambda: {"sub_user_id": str(results["create_sub_user"]["id"]),
                                     "traffic_limit": 2000}),
        ("reset_sub_user_usage", lambda: {"sub_user_ids": [str(results["create_sub_user"]["id"])]}),
        ("delete_sub_user", lambda: {"sub_user_id": str(results["create_sub_user"]["id"])}),
        ("add_whitelist_ip", lambda: {"ip": ip, "ports_count": 1, "name": "smoke"}),
        ("list_whitelist_ips", lambda: {}),
        ("remove_whitelist_ip", lambda: {"ip_id": str(results["add_whitelist_ip"]["ip_id"])}),
    ]


async def main() -> int:
    if not os.environ.get("NODEMAVEN_APIKEY"):
        print("set NODEMAVEN_APIKEY first")
        return 2
    password = Client().me()["proxy_password"]
    # Without the reveal flag, so no password - the account's or a new sub-user's - is printed.
    env = {k: v for k, v in os.environ.items() if k != "NODEMAVEN_MCP_REVEAL_PASSWORD"}
    params = StdioServerParameters(command=shutil.which("nodemaven-mcp"), env=env)
    leaks = 0
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            results: dict = {}
            calls = [(n, (lambda a=a: a)) for n, a in CALLS]
            if os.environ.get("NODEMAVEN_MCP_ALLOW_WRITE") == "1":
                calls += write_calls(results)
            for name, make_args in calls:
                try:
                    args = make_args()
                except (KeyError, TypeError):
                    print(f"{name}: skipped, an earlier step failed")
                    continue
                result = await session.call_tool(name, args)
                payload = result.structured_content or [c.text for c in result.content]
                if not result.is_error:
                    results[name] = payload
                text = json.dumps(payload)
                if password and password in text:
                    leaks += 1
                    print(f"{name}: LEAK - result contains the proxy password")
                    continue
                if name == "list_sub_users" and not result.is_error:
                    text = f"{len(payload.get('rows', []))} sub-users, next_page={payload.get('next_page')}"
                elif name == "list_locations" and args.get("kind") == "regions" and not result.is_error:
                    text = (f"{len(payload.get('rows', []))} rows, total={payload.get('total')}, "
                            f"next_offset={payload.get('next_offset')}")
                print(f"{name} {args}: error={result.is_error} {text[:300]}")
    print("LEAKS:", leaks)
    return 1 if leaks else 0


sys.exit(asyncio.run(main()))
