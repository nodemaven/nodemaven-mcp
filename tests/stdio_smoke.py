"""Talk to the installed `nodemaven-mcp` command over stdio, as an MCP client would.

No network: fake proxy credentials, and the gateway pointed at a closed local port.
Run: python tests/stdio_smoke.py
"""

import asyncio
import json
import os
import shutil

from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client


async def main() -> None:
    env = dict(os.environ)
    env.update({
        "NODEMAVEN_APIKEY": "test-key",
        "NODEMAVEN_LOGIN": "acct_user",
        "NODEMAVEN_PASSWORD": "p@ss",
        "NODEMAVEN_HOST": "127.0.0.1",
        "NODEMAVEN_PORT": "9",
    })
    params = StdioServerParameters(command=shutil.which("nodemaven-mcp"), env=env)
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            init = await session.initialize()
            print("server:", init.server_info.name)
            tools = await session.list_tools()
            print("tools:", sorted(t.name for t in tools.tools))
            for name, args in (
                ("proxy_url", {"country": "us", "session_id": "abc", "ttl": "10m"}),
                ("check_proxy", {"country": "us"}),
            ):
                result = await session.call_tool(name, args)
                payload = result.structured_content or [c.text for c in result.content]
                print(f"{name}: is_error={result.is_error} {json.dumps(payload)}")


asyncio.run(main())
