import asyncio
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from mcp.server.mcpserver.exceptions import ToolError
from nodemaven import NotFoundError, Page

import nodemaven_mcp.server as srv

SECRET = "s3cr@t:pw/1"


class FakeClient:
    def __init__(self):
        self.calls = []

    def me(self):
        self.calls.append(("me",))
        return {
            "proxy_username": "acct_user",
            "proxy_password": SECRET,
            "email": "owner@example.com",
            "data": 1024,
            "subscription_status": "active",
            "is_traffic_frozen": "false",
        }

    def sub_users(self, **filters):
        self.calls.append(("sub_users", filters))
        if filters.get("page", 1) > 1:
            return Page(results=[])
        return Page(results=[{"id": "1", "proxy_username": "sub1", "proxy_password": SECRET,
                              "is_default_user": False, "is_traffic_limited": True,
                              "used_traffic": 10, "traffic_limit": 100}])

    def countries(self, **filters):
        self.calls.append(("countries", filters))
        return Page(results=[{"name": "United States", "code": "us"}], count=1)

    def statistics_data(self, proxy_username, **filters):
        self.calls.append(("statistics_data", proxy_username, filters))
        return {"labels": ["00:00"], "data": [5]}

    def create_sub_user(self, proxy_username, proxy_password, **extra):
        self.calls.append(("create_sub_user", proxy_username, proxy_password, extra))
        return {"id": "7", "proxy_username": proxy_username, "proxy_password": proxy_password,
                "is_default_user": False, "is_traffic_limited": bool(extra),
                "traffic_limit": extra.get("traffic_limit", 0)}

    def update_sub_user(self, sub_user_id, **changes):
        self.calls.append(("update_sub_user", sub_user_id, changes))
        return {"id": sub_user_id, "proxy_username": "sub1", "proxy_password": SECRET, **changes}

    def reset_sub_user_usage(self, ids):
        self.calls.append(("reset_sub_user_usage", ids))
        return [{"id": i, "proxy_username": "sub1", "proxy_password": SECRET, "used_traffic": 0}
                for i in ids]

    def delete_sub_user(self, sub_user_id):
        self.calls.append(("delete_sub_user", sub_user_id))
        return {"message": "deleted"}

    def whitelist_ips(self, **filters):
        self.calls.append(("whitelist_ips", filters))
        if filters.get("page", 1) > 1:
            raise NotFoundError("404 past the end")
        return Page(results=[{"id": 3, "ip": "192.0.2.7", "user_id": 99, "protocol": "HTTP",
                              "ports": [10000, 10001], "number_of_proxies": 2}])

    def upsert_whitelist_ip(self, ip, ports_count, **extra):
        self.calls.append(("upsert_whitelist_ip", ip, ports_count, extra))
        return {"ip_id": 3, "message": "created"}

    def delete_whitelist_ip(self, ip_id):
        self.calls.append(("delete_whitelist_ip", ip_id))
        return {"message": "deleted"}

    def domain_statistics(self, proxy_username, **filters):
        self.calls.append(("domain_statistics", filters))
        return Page(results=[["www.amazon.com", 40, 34756266],
                             ["speed.cloudflare.com", 46, 47147592],
                             ["cdn.jsdelivr.net", 59, 60633404],
                             {"domain_name": "example.com", "requests": 1, "data": 99}])


@pytest.fixture
def fake(monkeypatch):
    for var in ("NODEMAVEN_LOGIN", "NODEMAVEN_PASSWORD", "NODEMAVEN_MCP_REVEAL_PASSWORD",
                "NODEMAVEN_MCP_ALLOW_WRITE", "NODEMAVEN_HOST", "NODEMAVEN_PORT"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("NODEMAVEN_APIKEY", "test-key")
    client = FakeClient()
    state = srv._State()
    state._client = client
    monkeypatch.setattr(srv, "state", state)
    return client


READ_TOOLS = {"proxy_url", "check_proxy", "test_proxy_on_site", "list_locations",
              "account_status", "traffic_stats", "top_domains", "list_sub_users",
              "list_whitelist_ips"}
WRITE_TOOLS = {"create_sub_user", "update_sub_user", "reset_sub_user_usage",
               "delete_sub_user", "add_whitelist_ip", "remove_whitelist_ip"}


def test_tools_are_registered():
    names = {t.name for t in asyncio.run(srv.server.list_tools())}
    assert names == READ_TOOLS | WRITE_TOOLS


def test_proxy_url_hides_password_by_default(fake):
    out = srv.proxy_url(country="us", session_id="abc", ttl="10m")
    assert out["username"] == "acct_user-country-us-sid-abc-ttl-10m"
    assert out["url"] == ("http://acct_user-country-us-sid-abc-ttl-10m:<PROXY_PASSWORD>"
                          "@gate.nodemaven.com:8080")
    assert out["password_included"] is False
    assert SECRET not in json.dumps(out)


def test_proxy_url_reveals_encoded_password_when_allowed(fake, monkeypatch):
    monkeypatch.setenv("NODEMAVEN_MCP_REVEAL_PASSWORD", "1")
    out = srv.proxy_url(country="us")
    assert out["url"] == "http://acct_user-country-us:s3cr%40t%3Apw%2F1@gate.nodemaven.com:8080"
    assert out["password_included"] is True


def test_proxy_url_socks5(fake):
    out = srv.proxy_url(protocol="socks5")
    assert out["url"].startswith("socks5h://acct_user:")
    assert out["port"] == 1080


def test_proxy_url_mobile_names_the_type_and_residential_leaves_it_out(fake):
    mobile = srv.proxy_url(country="us", connection_type="mobile")
    assert mobile["username"] == "acct_user-country-us-type-mobile"
    residential = srv.proxy_url(country="us", connection_type="residential")
    assert residential["username"] == "acct_user-country-us"


def test_check_and_site_test_take_the_connection_type(fake, monkeypatch):
    seen = []
    real = srv._build_proxy

    def spy(protocol, connection_type="residential", **params):
        proxy = real(protocol, connection_type, **params)
        seen.append(proxy.username)
        raise srv.NodeMavenError("stop here")

    monkeypatch.setattr(srv, "_build_proxy", spy)
    for call in (lambda: srv.check_proxy(connection_type="mobile"),
                 lambda: srv.test_proxy_on_site("https://example.com", connection_type="mobile")):
        with pytest.raises(ToolError):
            call()
    assert seen == ["acct_user-type-mobile"] * 2


def test_env_credentials_skip_the_api(fake, monkeypatch):
    monkeypatch.setenv("NODEMAVEN_LOGIN", "env_user")
    monkeypatch.setenv("NODEMAVEN_PASSWORD", "env_pw")
    assert srv.proxy_url()["username"] == "env_user"
    assert ("me",) not in fake.calls


def test_invalid_parameter_is_a_tool_error(fake):
    with pytest.raises(ToolError):
        srv.proxy_url(country="us-east")


def test_account_status_returns_allowlisted_fields_only(fake):
    out = srv.account_status()
    assert out == {"proxy_username": "acct_user", "data": 1024,
                   "subscription_status": "active", "is_traffic_frozen": "false"}


def test_sub_users_drop_passwords(fake):
    out = srv.list_sub_users()
    assert SECRET not in json.dumps(out)
    assert out["rows"][0]["proxy_username"] == "sub1"


def test_locations_pass_filters_and_cap_limit(fake):
    out = srv.list_locations("countries", limit=5000)
    assert out["rows"] == [{"name": "United States", "code": "us"}]
    assert fake.calls[-1] == ("countries", {"connection_type": "residential", "limit": "100", "offset": "0"})


def test_stats_default_to_today(fake):
    out = srv.traffic_stats()
    assert out == {"labels": ["00:00"], "data": [5]}
    assert fake.calls[-1] == ("statistics_data", "acct_user", {"period": "today"})


def test_missing_api_key_is_reported(monkeypatch):
    monkeypatch.delenv("NODEMAVEN_APIKEY", raising=False)
    monkeypatch.setattr(srv, "state", srv._State())
    with pytest.raises(ToolError, match="NODEMAVEN_APIKEY"):
        srv.account_status()


def test_top_domains_labels_columns_and_sorts_by_bytes(fake):
    out = srv.top_domains(limit=2)
    assert fake.calls[-1] == ("domain_statistics", {"limit": 1000, "period": "today"})
    assert out["rows"] == [
        {"domain": "cdn.jsdelivr.net", "requests": 59, "bytes": 60633404},
        {"domain": "speed.cloudflare.com", "requests": 46, "bytes": 47147592},
    ]


def test_locations_omit_unknown_total(fake):
    assert "total" in srv.list_locations("countries")
    fake.countries = lambda **f: Page(results=[])
    assert "total" not in srv.list_locations("countries")


def test_read_tools_are_read_only_and_write_tools_are_not():
    tools = {t.name: t.annotations for t in asyncio.run(srv.server.list_tools())}
    assert all(tools[name].read_only_hint for name in READ_TOOLS)
    assert not any(tools[name].read_only_hint for name in WRITE_TOOLS)
    assert {n for n in WRITE_TOOLS if tools[n].destructive_hint} == {
        "reset_sub_user_usage", "delete_sub_user", "remove_whitelist_ip"}


def test_locations_page_with_offset(fake):
    fake.countries = lambda **f: (fake.calls.append(("countries", f)),
                                  Page(results=[{"code": c} for c in "abc"], count=7))[1]
    out = srv.list_locations("countries", limit=3, offset=3)
    assert fake.calls[-1][1]["offset"] == "3"
    assert out["next_offset"] == 6 and out["total"] == 7
    fake.countries = lambda **f: Page(results=[{"code": "z"}], count=7)
    assert "next_offset" not in srv.list_locations("countries", limit=3, offset=6)


def test_locations_without_count_page_while_full(fake):
    fake.countries = lambda **f: Page(results=[{"code": c} for c in "ab"])
    assert srv.list_locations("countries", limit=2)["next_offset"] == 2
    assert "next_offset" not in srv.list_locations("countries", limit=5)


def test_sub_users_page(fake):
    first = srv.list_sub_users()
    assert first["next_page"] == 2 and fake.calls[-1] == ("sub_users", {"page": 1})
    last = srv.list_sub_users(page=2)
    assert last["rows"] == [] and "next_page" not in last


@pytest.fixture
def writes(fake, monkeypatch):
    monkeypatch.setenv("NODEMAVEN_MCP_ALLOW_WRITE", "1")
    return fake


@pytest.mark.parametrize("call", [
    lambda: srv.create_sub_user("new1"),
    lambda: srv.update_sub_user("1", traffic_limit=5),
    lambda: srv.reset_sub_user_usage(["1"]),
    lambda: srv.delete_sub_user("1"),
    lambda: srv.add_whitelist_ip("192.0.2.7", 1),
    lambda: srv.remove_whitelist_ip("3"),
])
def test_write_tools_refuse_unless_allowed(fake, call):
    with pytest.raises(ToolError, match="NODEMAVEN_MCP_ALLOW_WRITE"):
        call()
    assert fake.calls == []


def test_create_sub_user_generates_and_hides_the_password(writes):
    out = srv.create_sub_user("new1", traffic_limit=1000)
    _, username, password, extra = writes.calls[-1]
    assert username == "new1" and len(password) == 32
    assert extra == {"traffic_limit": 1000, "is_traffic_limited": True}
    assert out["password"] == "<PROXY_PASSWORD>"
    assert password not in json.dumps(out)


def test_create_sub_user_reveals_the_password_when_allowed(writes, monkeypatch):
    monkeypatch.setenv("NODEMAVEN_MCP_REVEAL_PASSWORD", "1")
    out = srv.create_sub_user("new1")
    assert out["password"] == writes.calls[-1][2]
    assert writes.calls[-1][3] == {}


def test_update_sub_user_needs_a_change_and_drops_the_password(writes):
    with pytest.raises(ToolError, match="Nothing to change"):
        srv.update_sub_user("1")
    out = srv.update_sub_user("1", traffic_limit=500, is_traffic_limited=True)
    assert writes.calls[-1] == ("update_sub_user", "1", {"traffic_limit": 500, "is_traffic_limited": True})
    assert SECRET not in json.dumps(out)


def test_reset_and_delete_sub_user(writes):
    out = srv.reset_sub_user_usage(["1", "2"])
    assert [r["id"] for r in out["rows"]] == ["1", "2"]
    assert SECRET not in json.dumps(out)
    assert srv.delete_sub_user("1") == {"deleted": "1"}
    assert writes.calls[-1] == ("delete_sub_user", "1")


def test_whitelist_listing_drops_fields_and_ends_on_404(fake):
    out = srv.list_whitelist_ips()
    assert out["rows"] == [{"id": 3, "ip": "192.0.2.7", "protocol": "HTTP",
                            "ports": [10000, 10001], "number_of_proxies": 2}]
    assert out["next_page"] == 2
    assert srv.list_whitelist_ips(page=2) == {"page": 2, "rows": []}


def test_add_whitelist_ip_sends_protocol_and_targeting(writes):
    out = srv.add_whitelist_ip("192.0.2.7", 2, country="us", city="")
    assert writes.calls[-1] == ("upsert_whitelist_ip", "192.0.2.7", 2,
                                {"name": None, "protocol": "HTTP", "country": "us"})
    assert out == {"ip_id": 3, "ip": "192.0.2.7", "message": "created"}
    assert srv.remove_whitelist_ip("3") == {"removed": "3"}


@pytest.mark.parametrize("status, body, blocked", [
    (200, b"<html>results</html>", None),
    (403, b"", "HTTP 403 (forbidden)"),
    (429, b"", "HTTP 429 (rate limited)"),
    (200, b"<title>Just a moment...</title>", "Cloudflare challenge"),
    (200, b"<div class='g-recaptcha'></div>", "captcha"),
    (202, b"<script src='https://x.awswaf.com/challenge.js'></script><noscript>"
          b"we need to verify that you're not a robot</noscript>", "AWS WAF challenge"),
])
def test_site_check_reads_the_status_and_the_page(fake, monkeypatch, status, body, blocked):
    seen = {}

    def fetch(proxy_url, url):
        seen["proxy"], seen["url"] = proxy_url, url
        return status, url, body

    monkeypatch.setattr(srv, "_fetch_through", fetch)
    out = srv.test_proxy_on_site("https://example.com", country="de")
    assert out["blocked"] == blocked
    assert out["ok"] is (blocked is None)
    assert out["bytes"] == len(body)
    assert "acct_user-country-de" in seen["proxy"]
    assert SECRET not in json.dumps(out)


def test_site_check_refuses_a_non_http_url(fake):
    with pytest.raises(ToolError, match="http or https"):
        srv.test_proxy_on_site("file:///etc/passwd")


def test_site_check_keeps_the_password_out_of_errors(fake, monkeypatch):
    def fetch(proxy_url, url):
        raise OSError(f"Tunnel connection failed via {proxy_url}")

    monkeypatch.setattr(srv, "_fetch_through", fetch)
    out = srv.test_proxy_on_site("https://example.com")
    assert out["ok"] is False and "OSError" in out["error"]
    assert "s3cr%40t" not in out["error"] and SECRET not in out["error"]


def test_a_full_page_with_a_captcha_widget_is_not_a_block(fake, monkeypatch):
    page = b"<form><div class='g-recaptcha'></div></form>" + b"x" * (srv.BLOCK_PAGE_MAX + 1)
    monkeypatch.setattr(srv, "_fetch_through", lambda proxy_url, url: (200, url, page))
    out = srv.test_proxy_on_site("https://example.com")
    assert out["ok"] is True and out["blocked"] is None


class FakeProxy(BaseHTTPRequestHandler):
    seen = []
    location = None

    def do_GET(self):
        FakeProxy.seen.append((self.path, self.headers.get("Proxy-Authorization")))
        if FakeProxy.location and self.path.endswith("/start"):
            self.send_response(302)
            self.send_header("Location", FakeProxy.location)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Length", "5")
        self.end_headers()
        self.wfile.write(b"hello")

    def log_message(self, *args):
        pass


@pytest.fixture
def fake_proxy(monkeypatch):
    FakeProxy.seen, FakeProxy.location = [], None
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), FakeProxy)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://u:p%40w@127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()


def test_site_check_goes_through_the_proxy(fake_proxy):
    status, _, body = srv._fetch_through(fake_proxy, "http://example.invalid/page")
    assert (status, body) == (200, b"hello")
    assert FakeProxy.seen == [("http://example.invalid/page", "Basic dTpwQHc=")]


def test_site_check_ignores_no_proxy(fake_proxy, monkeypatch):
    monkeypatch.setenv("NO_PROXY", "*")
    monkeypatch.setenv("no_proxy", "*")
    status, _, _ = srv._fetch_through(fake_proxy, "http://example.invalid/page")
    assert status == 200 and FakeProxy.seen[0][0] == "http://example.invalid/page"


def test_site_check_does_not_follow_a_redirect_off_http(fake_proxy):
    FakeProxy.location = "ftp://files.example.invalid/x"
    status, final_url, _ = srv._fetch_through(fake_proxy, "http://example.invalid/start")
    assert status == 302 and final_url == "http://example.invalid/start"
    assert len(FakeProxy.seen) == 1


def test_site_check_follows_an_http_redirect_through_the_proxy(fake_proxy):
    FakeProxy.location = "http://example.invalid/next"
    status, final_url, body = srv._fetch_through(fake_proxy, "http://example.invalid/start")
    assert (status, final_url, body) == (200, "http://example.invalid/next", b"hello")
    assert [path for path, _ in FakeProxy.seen] == ["http://example.invalid/start",
                                                     "http://example.invalid/next"]


def test_missing_api_key_points_to_sign_up(monkeypatch):
    monkeypatch.delenv("NODEMAVEN_APIKEY", raising=False)
    monkeypatch.setattr(srv, "state", srv._State())
    with pytest.raises(ToolError, match="accounts/signup.*MCPNM"):
        srv.account_status()


def test_account_status_notes_an_empty_balance(fake, monkeypatch):
    assert "note" not in srv.account_status()
    me = fake.me
    monkeypatch.setattr(fake, "me", lambda: {**me(), "data": 0})
    out = srv.account_status()
    assert "No traffic left" in out["note"] and "MCPNM" in out["note"]
