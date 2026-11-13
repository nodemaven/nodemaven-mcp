# NodeMaven proxies

This extension connects you to the user's NodeMaven account: residential and mobile proxies
for scraping and automation.

## Setup

The server reads the dashboard API key from `NODEMAVEN_APIKEY` in the environment Gemini CLI
starts in (dashboard, Profile; not the proxy password). If tools answer that the key is
missing, ask the user to set it and restart the session. No account yet: NodeMaven gives free
traffic with the code MCPNM.

## Tools

- `proxy_url`: a proxy URL for a country, region, city or ISP, with a sticky session when the
  user needs the same IP across requests. Passwords are masked unless the user enabled them.
- `check_proxy` and `test_proxy_on_site`: the exit IP and its location, and whether a target
  site answers through the proxy.
- `list_locations`: countries, regions, cities and ISPs available for targeting.
- `account_status`, `traffic_stats`, `top_domains`: traffic left and usage.
- Sub-users and whitelisted IPs: listing is always allowed; creating, changing and deleting
  them needs `NODEMAVEN_MCP_ALLOW_WRITE=1`. Confirm with the user before any of these.

Prefer `proxy_url` with a sticky session for scraping one site, and check the exit with
`check_proxy` before a long run.
