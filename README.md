# nodemaven-mcp

An [MCP](https://modelcontextprotocol.io) server for [NodeMaven](https://nodemaven.com)
residential proxies. It lets an AI assistant build proxy strings with geo-targeting
and sticky sessions, check that a proxy connects and where it exits, look up
locations, and read traffic usage.

It is read-only: nothing in your account is created, changed or deleted.

<!-- mcp-name: io.github.nodemaven/nodemaven-mcp -->

## Tools

| Tool | What it does |
|---|---|
| `proxy_url` | Proxy string for a country, region, city or ISP, with an optional sticky session and its lifetime. HTTP or SOCKS5. |
| `check_proxy` | Opens one connection through the proxy and returns the status, the exit IP and the time it took. |
| `list_locations` | Countries, regions, cities and ISPs available for targeting, with the codes `proxy_url` takes. |
| `account_status` | Remaining traffic, subscription status, whether traffic is frozen. |
| `traffic_stats` | Traffic used over time. |
| `top_domains` | Domains reached through the proxy, with traffic per domain. |
| `list_sub_users` | Sub-users with their usage and limits. |

## Setup

You need an API key from the NodeMaven dashboard. The proxy username and password are
read from the account through that key, so nothing else is required.

Claude Desktop (`claude_desktop_config.json`), Cursor and other MCP clients:

```json
{
  "mcpServers": {
    "nodemaven": {
      "command": "uvx",
      "args": ["nodemaven-mcp"],
      "env": { "NODEMAVEN_APIKEY": "your-api-key" }
    }
  }
}
```

Without `uv`: `pip install nodemaven-mcp` and use `"command": "nodemaven-mcp"`.

| Variable | |
|---|---|
| `NODEMAVEN_APIKEY` | Required. |
| `NODEMAVEN_LOGIN`, `NODEMAVEN_PASSWORD` | Optional. Proxy credentials to use instead of the account's own, e.g. a sub-user. |
| `NODEMAVEN_MCP_REVEAL_PASSWORD` | `1` puts the real password into `proxy_url` output. Off by default. |

## Credentials

Tool results go into the model's context and usually into the chat history, so the
server keeps secrets out of them:

- `proxy_url` returns the password as `<PROXY_PASSWORD>` unless
  `NODEMAVEN_MCP_REVEAL_PASSWORD=1` is set.
- API responses are reduced to a fixed list of fields; proxy passwords and the
  account email are never returned.

## Development

```bash
uv sync
uv run pytest
```

Built on the [`nodemaven`](https://pypi.org/project/nodemaven/) Python SDK.

## License

MIT
