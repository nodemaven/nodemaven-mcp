"""MCP server for NodeMaven residential proxies.

Read-only: it builds proxy strings, checks them, and reads locations, usage and
statistics from the NodeMaven API. It never changes the account.

Credentials stay in this process. API responses are reduced to an allowlist of
fields before they are returned, and the proxy password is replaced with a
placeholder unless ``NODEMAVEN_MCP_REVEAL_PASSWORD=1`` is set.
"""

from __future__ import annotations

import os
from typing import Any, Literal, Optional
from urllib.parse import quote

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations
from nodemaven import Client, NodeMavenError, Proxy

PASSWORD_PLACEHOLDER = "<PROXY_PASSWORD>"
SOCKS5_PORT = 1080
MAX_ROWS = 100
DOMAIN_FETCH_LIMIT = 1000

ACCOUNT_FIELDS = ("proxy_username", "data", "subscription_status", "is_traffic_frozen")
SUB_USER_FIELDS = (
    "id",
    "proxy_username",
    "is_default_user",
    "is_traffic_limited",
    "used_traffic",
    "traffic_limit",
)
LOCATION_KINDS = ("countries", "regions", "cities", "isps")

server = MCPServer(
    name="nodemaven",
    instructions=(
        "Tools for NodeMaven residential proxies. Use proxy_url to get a proxy "
        "string with country/region/city/ISP targeting and sticky sessions, "
        "check_proxy to confirm it connects and see the exit IP, list_locations "
        "to find valid location codes, and account_status, traffic_stats, "
        "top_domains and list_sub_users for usage."
    ),
)


class _State:
    def __init__(self) -> None:
        self._client: Optional[Client] = None
        self._credentials: Optional[tuple[str, str]] = None

    def client(self) -> Client:
        if self._client is None:
            if not os.environ.get("NODEMAVEN_APIKEY"):
                raise NodeMavenError(
                    "NODEMAVEN_APIKEY is not set. Create an API key in the NodeMaven "
                    "dashboard and pass it in the server's environment."
                )
            self._client = Client()
        return self._client

    def credentials(self) -> tuple[str, str]:
        if self._credentials is None:
            login = os.environ.get("NODEMAVEN_LOGIN")
            password = os.environ.get("NODEMAVEN_PASSWORD")
            if not (login and password):
                me = self.client().me()
                login, password = me["proxy_username"], me["proxy_password"]
            self._credentials = (login, password)
        return self._credentials


state = _State()

READ_ONLY = ToolAnnotations(read_only_hint=True, destructive_hint=False, open_world_hint=True)


def _reveal_password() -> bool:
    return os.environ.get("NODEMAVEN_MCP_REVEAL_PASSWORD") == "1"


def _pick(row: Any, fields: tuple[str, ...]) -> dict[str, Any]:
    return {k: row[k] for k in fields if isinstance(row, dict) and k in row}


def _params(**values: Any) -> dict[str, str]:
    return {k: str(v) for k, v in values.items() if v not in (None, "")}


def _build_proxy(protocol: str, **params: Any) -> Proxy:
    login, password = state.credentials()
    port = SOCKS5_PORT if protocol == "socks5" else None
    return Proxy(login=login, password=password, port=port, **_params(**params))


@server.tool(annotations=READ_ONLY)
def proxy_url(
    country: Optional[str] = None,
    region: Optional[str] = None,
    city: Optional[str] = None,
    isp: Optional[str] = None,
    session_id: Optional[str] = None,
    ttl: Optional[str] = None,
    filter: Optional[str] = None,
    protocol: Literal["http", "socks5"] = "http",
) -> dict[str, Any]:
    """Build a NodeMaven proxy string.

    Targeting goes into the username. Without session_id every request gets a
    new exit IP; with session_id the same exit is kept for ttl (e.g. "10m",
    "1h", "24h"). country is a two-letter code; region, city and isp take the
    codes from list_locations. filter is the IP quality filter, e.g. "medium".
    The password is a placeholder unless the server allows revealing it.
    """
    try:
        proxy = _build_proxy(
            protocol,
            country=country,
            region=region,
            city=city,
            isp=isp,
            sid=session_id,
            ttl=ttl,
            filter=filter,
        )
    except NodeMavenError as e:
        raise ToolError(str(e)) from e
    scheme = "socks5h" if protocol == "socks5" else "http"
    host, port = proxy.server.rsplit(":", 1)
    if _reveal_password():
        password = quote(state.credentials()[1], safe="")
    else:
        password = PASSWORD_PLACEHOLDER
    return {
        "url": f"{scheme}://{quote(proxy.username, safe='')}:{password}@{host}:{port}",
        "username": proxy.username,
        "host": host,
        "port": int(port),
        "password_included": _reveal_password(),
    }


@server.tool(annotations=READ_ONLY)
def check_proxy(
    country: Optional[str] = None,
    region: Optional[str] = None,
    city: Optional[str] = None,
    isp: Optional[str] = None,
    session_id: Optional[str] = None,
    ttl: Optional[str] = None,
    filter: Optional[str] = None,
) -> dict[str, Any]:
    """Open one connection through the proxy and report the result.

    Sends no traffic through the tunnel. Returns the gateway status, the exit
    IP when the gateway reports it, and how long the connection took. A 407 can
    mean a wrong parameter value as well as wrong credentials.
    """
    try:
        result = _build_proxy(
            "http",
            country=country,
            region=region,
            city=city,
            isp=isp,
            sid=session_id,
            ttl=ttl,
            filter=filter,
        ).check()
    except NodeMavenError as e:
        raise ToolError(str(e)) from e
    return {
        "ok": result.ok,
        "status": result.status,
        "reason": result.reason,
        "exit_ip": result.exit_ip,
        "seconds": round(result.elapsed, 3),
        "meaning": result.meaning,
    }


@server.tool(annotations=READ_ONLY)
def list_locations(
    kind: Literal["countries", "regions", "cities", "isps"],
    country_code: Optional[str] = None,
    region_code: Optional[str] = None,
    connection_type: Literal["residential", "mobile"] = "residential",
    limit: int = 50,
) -> dict[str, Any]:
    """List locations available for targeting, with the codes proxy_url takes.

    regions need country_code; cities and isps can be narrowed by country_code
    and region_code.
    """
    filters = _params(
        country__code=country_code.lower() if country_code else None,
        region__code=region_code,
        connection_type=connection_type,
        limit=max(1, min(limit, MAX_ROWS)),
    )
    try:
        page = getattr(state.client(), kind)(**filters)
    except NodeMavenError as e:
        raise ToolError(str(e)) from e
    out: dict[str, Any] = {"kind": kind, "rows": list(page.results)[:MAX_ROWS]}
    if page.count is not None:
        out["total"] = page.count
    return out


@server.tool(annotations=READ_ONLY)
def account_status() -> dict[str, Any]:
    """Remaining traffic (bytes), subscription status and whether traffic is frozen."""
    try:
        return _pick(state.client().me(), ACCOUNT_FIELDS)
    except NodeMavenError as e:
        raise ToolError(str(e)) from e


def _domain_row(row: Any) -> Optional[dict[str, Any]]:
    # Rows arrive as [domain, requests, bytes]; the API documents the same fields
    # as an object (domain_name, requests, data), which is accepted too.
    if isinstance(row, (list, tuple)) and len(row) == 3:
        domain, requests, data = row
    elif isinstance(row, dict):
        domain, requests, data = row.get("domain_name"), row.get("requests"), row.get("data")
    else:
        return None
    return {"domain": domain, "requests": requests, "bytes": data}


def _stats_filters(period: Optional[str], start: Optional[str], end: Optional[str]) -> dict[str, str]:
    if not (period or start or end):
        period = "today"
    return _params(period=period, start=start, end=end)


@server.tool(annotations=READ_ONLY)
def traffic_stats(
    period: Optional[Literal["today", "hours24"]] = None,
    start: Optional[str] = None,
    end: Optional[str] = None,
) -> dict[str, Any]:
    """Traffic used over time, as parallel labels and data arrays.

    Pass period, or start and end as dd-mm-yyyy (not ISO). Defaults to today.
    """
    try:
        login = state.credentials()[0]
        stats = state.client().statistics_data(login, **_stats_filters(period, start, end))
    except NodeMavenError as e:
        raise ToolError(str(e)) from e
    return {"labels": stats.get("labels", []), "data": stats.get("data", [])}


@server.tool(annotations=READ_ONLY)
def top_domains(
    period: Optional[Literal["today", "hours24"]] = None,
    start: Optional[str] = None,
    end: Optional[str] = None,
    limit: int = 20,
) -> dict[str, Any]:
    """Domains reached through the proxy, largest traffic first, with bytes and request counts.

    Pass period, or start and end as dd-mm-yyyy (not ISO). Defaults to today.
    """
    try:
        login = state.credentials()[0]
        page = state.client().domain_statistics(
            login, limit=DOMAIN_FETCH_LIMIT, **_stats_filters(period, start, end)
        )
    except NodeMavenError as e:
        raise ToolError(str(e)) from e
    rows = [r for r in map(_domain_row, page.results) if r is not None]
    rows.sort(key=lambda r: r["bytes"] if isinstance(r["bytes"], (int, float)) else -1, reverse=True)
    return {"rows": rows[: max(1, min(limit, MAX_ROWS))]}


@server.tool(annotations=READ_ONLY)
def list_sub_users() -> dict[str, Any]:
    """Sub-users of the account with their traffic usage and limits. No passwords."""
    try:
        page = state.client().sub_users()
    except NodeMavenError as e:
        raise ToolError(str(e)) from e
    return {"rows": [_pick(row, SUB_USER_FIELDS) for row in page.results]}


def main() -> None:
    server.run("stdio")


if __name__ == "__main__":
    main()
