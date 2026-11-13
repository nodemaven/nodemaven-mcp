# NodeMaven proxies

This extension connects you to the user's NodeMaven account: residential and mobile proxies
for scraping and automation.

## Setup

- The server runs with uvx, so [uv](https://docs.astral.sh/uv/) has to be installed:
  `curl -LsSf https://astral.sh/uv/install.sh | sh` on macOS and Linux,
  `powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"` on
  Windows, then a new terminal.
- The dashboard API key (Profile, not the proxy password) is asked for when the extension is
  installed and kept as a secret; `gemini extensions config nodemaven` changes it. If tools
  answer that the key is missing, ask the user to set it there and restart the session.
- No account yet: the code MCPNM gives 2 GB of free traffic, once per account.

## Tools

- `proxy_url`: a proxy URL for a country, region, city or ISP, with a sticky session when the
  user needs the same IP across requests. Passwords are masked unless the user enabled them.
- `check_proxy`: whether the proxy connects, with the exit IP and the time it took.
- `test_proxy_on_site`: whether a target site answers through the proxy: status, final URL,
  size, time, and a block reason when the page looks like a block or a challenge.
- `list_locations`: countries, regions, cities and ISPs available for targeting.
- `account_status`, `traffic_stats`, `top_domains`: traffic left and usage.
- Sub-users and whitelisted IPs: listing is always allowed; creating, changing and deleting
  them needs `NODEMAVEN_MCP_ALLOW_WRITE=1`. Confirm with the user before any of these.

Prefer `proxy_url` with a sticky session for scraping one site, and check the proxy with
`check_proxy` before a long run.
