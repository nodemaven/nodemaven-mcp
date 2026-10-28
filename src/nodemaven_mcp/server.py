"""MCP server for NodeMaven residential proxies.

It builds proxy strings, checks them, tests them against a site, and reads
locations, usage, statistics, sub-users and whitelisted IPs from the NodeMaven
API. Tools that change the account (sub-users, whitelisted IPs) refuse to run
unless ``NODEMAVEN_MCP_ALLOW_WRITE=1`` is set.

Credentials stay in this process. API responses are reduced to an allowlist of
fields before they are returned, and proxy passwords are replaced with a
placeholder unless ``NODEMAVEN_MCP_REVEAL_PASSWORD=1`` is set.
"""

from __future__ import annotations

import base64
import os
import secrets
import time
import urllib.error
import urllib.request
from typing import Any, Literal, Optional
from urllib.parse import quote, unquote, urlsplit

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations
from nodemaven import Client, NodeMavenError, NotFoundError, Proxy

PASSWORD_PLACEHOLDER = "<PROXY_PASSWORD>"
SIGNUP_URL = "https://dashboard.nodemaven.com/accounts/signup/"
PROMO = "the code MCPNM gives 2 GB of free traffic, once per account"
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
WHITELIST_FIELDS = (
    "id",
    "ip",
    "name",
    "protocol",
    "ports",
    "number_of_proxies",
    "type",
    "country_code",
    "region_code",
    "city_code",
    "isp_code",
    "sticky",
    "ttl",
    "quality_filter_enabled",
)
LOCATION_KINDS = ("countries", "regions", "cities", "isps")

SITE_TIMEOUT = 30
SITE_READ_LIMIT = 2 * 2**20
SITE_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36"
)
BLOCK_PAGE_MAX = 64 * 1024
BLOCK_STATUSES = {401: "unauthorized", 403: "forbidden", 407: "proxy auth",
                  429: "rate limited", 503: "unavailable"}
BLOCK_MARKERS = (
    ("awswaf", "AWS WAF challenge"),
    ("not a robot", "robot check"),
    ("captcha", "captcha"),
    ("cf-chl", "Cloudflare challenge"),
    ("just a moment...", "Cloudflare challenge"),
    ("access denied", "access denied"),
    ("unusual traffic", "unusual traffic page"),
    ("are you a robot", "robot check"),
)

server = MCPServer(
    name="nodemaven",
    instructions=(
        "Tools for NodeMaven residential proxies. Use proxy_url to get a proxy "
        "string with country/region/city/ISP targeting and sticky sessions, "
        "check_proxy to confirm it connects and see the exit IP, test_proxy_on_site "
        "to see whether a site answers through the proxy, list_locations to find "
        "valid location codes, and account_status, traffic_stats, top_domains, "
        "list_sub_users and list_whitelist_ips for the account. create_sub_user, "
        "update_sub_user, reset_sub_user_usage, delete_sub_user, add_whitelist_ip "
        "and remove_whitelist_ip change the account: confirm with the user before "
        "calling them. They work only when the server allows writes."
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
                    "dashboard and pass it in the server's environment. No account yet? "
                    f"Sign up at {SIGNUP_URL} - {PROMO}."
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
WRITE = ToolAnnotations(read_only_hint=False, destructive_hint=False, open_world_hint=True)
DESTRUCTIVE = ToolAnnotations(read_only_hint=False, destructive_hint=True, open_world_hint=True)


def _reveal_password() -> bool:
    return os.environ.get("NODEMAVEN_MCP_REVEAL_PASSWORD") == "1"


def _require_write() -> None:
    if os.environ.get("NODEMAVEN_MCP_ALLOW_WRITE") != "1":
        raise ToolError(
            "This tool changes the NodeMaven account and writes are off. Set "
            "NODEMAVEN_MCP_ALLOW_WRITE=1 in the server's environment to allow them."
        )


def _pick(row: Any, fields: tuple[str, ...]) -> dict[str, Any]:
    return {k: row[k] for k in fields if isinstance(row, dict) and k in row}


def _params(**values: Any) -> dict[str, str]:
    return {k: str(v) for k, v in values.items() if v not in (None, "")}


def _build_proxy(protocol: str, connection_type: str = "residential", **params: Any) -> Proxy:
    login, password = state.credentials()
    port = SOCKS5_PORT if protocol == "socks5" else None
    # Without `type` the gateway draws from the residential pool, so only mobile
    # is named: residential usernames stay as they were, and so do their sessions.
    if connection_type == "mobile":
        params["type"] = "mobile"
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
    connection_type: Literal["residential", "mobile"] = "residential",
) -> dict[str, Any]:
    """Build a NodeMaven proxy string.

    Targeting goes into the username. Without session_id every request gets a
    new exit IP; with session_id the same exit is kept for ttl (e.g. "10m",
    "1h", "24h"). country is a two-letter code; region, city and isp take the
    codes from list_locations. filter is the IP quality filter, e.g. "medium".
    connection_type picks residential or mobile IPs; for mobile, take the
    location codes from list_locations with connection_type="mobile".
    The password is a placeholder unless the server allows revealing it.
    """
    try:
        proxy = _build_proxy(
            protocol,
            connection_type,
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
    connection_type: Literal["residential", "mobile"] = "residential",
) -> dict[str, Any]:
    """Open one connection through the proxy and report the result.

    Sends no traffic through the tunnel. Returns the gateway status, the exit
    IP when the gateway reports it, and how long the connection took. A 407 can
    mean a wrong parameter value as well as wrong credentials. For mobile, take
    the location codes from list_locations with connection_type="mobile".
    """
    try:
        result = _build_proxy(
            "http",
            connection_type,
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


class _ThroughProxy(urllib.request.BaseHandler):
    """Routes every http and https request through the proxy.

    ``ProxyHandler`` consults ``NO_PROXY`` and the system bypass list, which would
    send a matching site directly from this machine and report it as a proxy test.
    """

    handler_order = 100  # before the HTTP(S) handlers, like ProxyHandler

    def __init__(self, proxy_url: str) -> None:
        parts = urlsplit(proxy_url)
        self.server = f"{parts.hostname}:{parts.port}"
        user_pass = f"{unquote(parts.username or '')}:{unquote(parts.password or '')}"
        self.auth = "Basic " + base64.b64encode(user_pass.encode()).decode("ascii")

    def _route(self, req: urllib.request.Request) -> None:
        req.add_header("Proxy-Authorization", self.auth)
        req.set_proxy(self.server, "http")

    http_open = https_open = _route


class _HttpRedirectsOnly(urllib.request.HTTPRedirectHandler):
    """Stops at a redirect to anything but http or https, which the proxy does not carry."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        if urlsplit(newurl).scheme not in ("http", "https"):
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _fetch_through(proxy_url: str, url: str) -> tuple[int, str, bytes]:
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}), _ThroughProxy(proxy_url), _HttpRedirectsOnly
    )
    request = urllib.request.Request(url, headers={
        "User-Agent": SITE_USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
    })
    deadline = time.monotonic() + SITE_TIMEOUT
    try:
        response = opener.open(request, timeout=SITE_TIMEOUT)
    except urllib.error.HTTPError as e:
        response = e
    with response:
        body = bytearray()
        while len(body) < SITE_READ_LIMIT and time.monotonic() < deadline:
            chunk = response.read(min(64 * 1024, SITE_READ_LIMIT - len(body)))
            if not chunk:
                break
            body += chunk
        return response.getcode(), response.geturl(), bytes(body)


def _block_reason(status: int, body: bytes) -> Optional[str]:
    if status in BLOCK_STATUSES:
        return f"HTTP {status} ({BLOCK_STATUSES[status]})"
    # Challenge pages are small; a full page that merely embeds a captcha widget
    # or mentions "access denied" is not a refusal.
    if status == 200 and len(body) > BLOCK_PAGE_MAX:
        return None
    text = body.decode("utf-8", "replace").lower()
    for marker, label in BLOCK_MARKERS:
        if marker in text:
            return label
    return None


@server.tool(annotations=READ_ONLY)
def test_proxy_on_site(
    url: str,
    country: Optional[str] = None,
    region: Optional[str] = None,
    city: Optional[str] = None,
    isp: Optional[str] = None,
    session_id: Optional[str] = None,
    ttl: Optional[str] = None,
    filter: Optional[str] = None,
    connection_type: Literal["residential", "mobile"] = "residential",
) -> dict[str, Any]:
    """Request one page of a site through the proxy and say whether it answered.

    Sends one GET and reads at most 2 MB. Returns the status, the final URL,
    the size and time, and a block reason when the status or the page looks like
    a refusal (403, 429, a captcha or a challenge page). The page itself is not
    returned. A plain HTTP request is a weaker test than a browser: a site that
    needs JavaScript can refuse it and still serve the same proxy in a browser.
    For mobile, take the location codes from list_locations with
    connection_type="mobile".
    """
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ToolError("url must be an http or https address, e.g. https://example.com")
    try:
        proxy = _build_proxy(
            "http",
            connection_type,
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
    started = time.monotonic()
    try:
        status, final_url, body = _fetch_through(proxy.url(), url)
    except (OSError, ValueError) as e:
        message = str(e)
        secret = state.credentials()[1]
        for form in (quote(secret, safe=""), secret):
            message = message.replace(form, PASSWORD_PLACEHOLDER)
        return {"ok": False, "error": f"{type(e).__name__}: {message}",
                "seconds": round(time.monotonic() - started, 3)}
    blocked = _block_reason(status, body)
    return {
        "ok": blocked is None and 200 <= status < 400,
        "status": status,
        "final_url": final_url,
        "bytes": len(body),
        "seconds": round(time.monotonic() - started, 3),
        "blocked": blocked,
    }


@server.tool(annotations=READ_ONLY)
def list_locations(
    kind: Literal["countries", "regions", "cities", "isps"],
    country_code: Optional[str] = None,
    region_code: Optional[str] = None,
    connection_type: Literal["residential", "mobile"] = "residential",
    limit: int = 50,
    offset: int = 0,
) -> dict[str, Any]:
    """List locations available for targeting, with the codes proxy_url takes.

    regions need country_code; cities and isps can be narrowed by country_code
    and region_code. At most 100 rows per call: when next_offset is returned,
    call again with offset=next_offset for the rest.
    """
    limit = max(1, min(limit, MAX_ROWS))
    offset = max(0, offset)
    filters = _params(
        country__code=country_code.lower() if country_code else None,
        region__code=region_code,
        connection_type=connection_type,
        limit=limit,
        offset=offset,
    )
    try:
        page = getattr(state.client(), kind)(**filters)
    except NodeMavenError as e:
        raise ToolError(str(e)) from e
    rows = list(page.results)[:limit]
    out: dict[str, Any] = {"kind": kind, "offset": offset, "rows": rows}
    if page.count is not None:
        out["total"] = page.count
    more = offset + len(rows) < page.count if page.count is not None else len(rows) == limit
    if more:
        out["next_offset"] = offset + len(rows)
    return out


@server.tool(annotations=READ_ONLY)
def account_status() -> dict[str, Any]:
    """Remaining traffic (bytes), subscription status and whether traffic is frozen."""
    try:
        out = _pick(state.client().me(), ACCOUNT_FIELDS)
    except NodeMavenError as e:
        raise ToolError(str(e)) from e
    if isinstance(out.get("data"), (int, float)) and out["data"] <= 0:
        out["note"] = f"No traffic left. Top up in the NodeMaven dashboard; {PROMO}."
    return out


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
def list_sub_users(page: int = 1) -> dict[str, Any]:
    """Sub-users of the account with their traffic usage and limits. No passwords.

    Paged from page 1. When next_page is returned, call again with it for the
    rest; a page past the end comes back empty.
    """
    page = max(1, page)
    try:
        result = state.client().sub_users(page=page)
    except NodeMavenError as e:
        raise ToolError(str(e)) from e
    rows = [_pick(row, SUB_USER_FIELDS) for row in result.results]
    out: dict[str, Any] = {"page": page, "rows": rows}
    if rows:
        out["next_page"] = page + 1
    return out


@server.tool(annotations=WRITE)
def create_sub_user(
    username: str,
    traffic_limit: Optional[int] = None,
) -> dict[str, Any]:
    """Create a sub-user with its own proxy login. Changes the account.

    The password is generated here. It is returned only if the server allows
    revealing passwords; otherwise the user reads it in the dashboard.
    traffic_limit is in the same unit list_sub_users shows for traffic_limit and
    used_traffic; leave it out for no limit.
    """
    _require_write()
    password = secrets.token_hex(16)
    limits: dict[str, Any] = {}
    if traffic_limit is not None:
        limits = {"traffic_limit": traffic_limit, "is_traffic_limited": True}
    try:
        created = state.client().create_sub_user(username, password, **limits)
    except NodeMavenError as e:
        raise ToolError(str(e)) from e
    out = _pick(created, SUB_USER_FIELDS)
    out["password"] = password if _reveal_password() else PASSWORD_PLACEHOLDER
    return out


@server.tool(annotations=WRITE)
def update_sub_user(
    sub_user_id: str,
    traffic_limit: Optional[int] = None,
    is_traffic_limited: Optional[bool] = None,
) -> dict[str, Any]:
    """Change a sub-user's traffic limit, or turn the limit on or off. Changes the account."""
    _require_write()
    changes: dict[str, Any] = {}
    if is_traffic_limited is not None:
        changes["is_traffic_limited"] = is_traffic_limited
    if traffic_limit is not None:
        changes["traffic_limit"] = traffic_limit
    if not changes:
        raise ToolError("Nothing to change: pass traffic_limit or is_traffic_limited.")
    try:
        updated = state.client().update_sub_user(sub_user_id, **changes)
    except NodeMavenError as e:
        raise ToolError(str(e)) from e
    return _pick(updated, SUB_USER_FIELDS)


@server.tool(annotations=DESTRUCTIVE)
def reset_sub_user_usage(sub_user_ids: list[str]) -> dict[str, Any]:
    """Set the recorded traffic of one or more sub-users back to zero. Changes the account."""
    _require_write()
    if not sub_user_ids:
        raise ToolError("Pass at least one sub-user id.")
    try:
        rows = state.client().reset_sub_user_usage(sub_user_ids)
    except NodeMavenError as e:
        raise ToolError(str(e)) from e
    rows = rows if isinstance(rows, list) else [rows]
    return {"rows": [_pick(row, SUB_USER_FIELDS) for row in rows]}


@server.tool(annotations=DESTRUCTIVE)
def delete_sub_user(sub_user_id: str) -> dict[str, Any]:
    """Delete a sub-user. Its proxy login stops working. Cannot be undone."""
    _require_write()
    try:
        state.client().delete_sub_user(sub_user_id)
    except NodeMavenError as e:
        raise ToolError(str(e)) from e
    return {"deleted": sub_user_id}


@server.tool(annotations=READ_ONLY)
def list_whitelist_ips(page: int = 1) -> dict[str, Any]:
    """IP addresses allowed to use the proxy without a password, with their ports and targeting.

    Paged from page 1. When next_page is returned, call again with it for the rest.
    """
    page = max(1, page)
    try:
        result = state.client().whitelist_ips(page=page)
    except NotFoundError:
        if page == 1:
            raise ToolError("The whitelist endpoint answered 404.") from None
        return {"page": page, "rows": []}
    except NodeMavenError as e:
        raise ToolError(str(e)) from e
    rows = [_pick(row, WHITELIST_FIELDS) for row in result.results]
    out: dict[str, Any] = {"page": page, "rows": rows}
    if rows:
        out["next_page"] = page + 1
    return out


@server.tool(annotations=WRITE)
def add_whitelist_ip(
    ip: str,
    ports_count: int,
    protocol: Literal["HTTP", "SOCKS5"] = "HTTP",
    name: Optional[str] = None,
    country: Optional[str] = None,
    region: Optional[str] = None,
    city: Optional[str] = None,
    isp: Optional[str] = None,
) -> dict[str, Any]:
    """Allow an IP address to use the proxy without a password. Changes the account.

    ports_count is how many proxy ports the address gets. country, region, city
    and isp take the codes from list_locations. An address removed in the last
    hour can be refused as already whitelisted for a while.
    """
    _require_write()
    targeting = _params(country=country, region=region, city=city, isp=isp)
    try:
        added = state.client().upsert_whitelist_ip(
            ip, ports_count, name=name, protocol=protocol, **targeting
        )
    except NodeMavenError as e:
        raise ToolError(str(e)) from e
    return {"ip_id": added.get("ip_id"), "ip": ip, "message": added.get("message")}


@server.tool(annotations=DESTRUCTIVE)
def remove_whitelist_ip(ip_id: str) -> dict[str, Any]:
    """Remove an address from the whitelist, by the id list_whitelist_ips or add_whitelist_ip gave."""
    _require_write()
    try:
        state.client().delete_whitelist_ip(ip_id)
    except NodeMavenError as e:
        raise ToolError(str(e)) from e
    return {"removed": ip_id}


def main() -> None:
    server.run("stdio")


if __name__ == "__main__":
    main()
