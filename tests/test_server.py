import asyncio
import json

import pytest
from mcp.server.mcpserver.exceptions import ToolError
from nodemaven import Page

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
        return Page(results=[{"id": "1", "proxy_username": "sub1", "proxy_password": SECRET,
                              "is_default_user": False, "is_traffic_limited": True,
                              "used_traffic": 10, "traffic_limit": 100}])

    def countries(self, **filters):
        self.calls.append(("countries", filters))
        return Page(results=[{"name": "United States", "code": "us"}], count=1)

    def statistics_data(self, proxy_username, **filters):
        self.calls.append(("statistics_data", proxy_username, filters))
        return {"labels": ["00:00"], "data": [5]}

    def domain_statistics(self, proxy_username, **filters):
        self.calls.append(("domain_statistics", filters))
        return Page(results=[["www.amazon.com", 40, 34756266],
                             ["speed.cloudflare.com", 46, 47147592],
                             ["cdn.jsdelivr.net", 59, 60633404],
                             {"domain_name": "example.com", "requests": 1, "data": 99}])


@pytest.fixture
def fake(monkeypatch):
    for var in ("NODEMAVEN_LOGIN", "NODEMAVEN_PASSWORD", "NODEMAVEN_MCP_REVEAL_PASSWORD",
                "NODEMAVEN_HOST", "NODEMAVEN_PORT"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("NODEMAVEN_APIKEY", "test-key")
    client = FakeClient()
    state = srv._State()
    state._client = client
    monkeypatch.setattr(srv, "state", state)
    return client


def test_tools_are_registered():
    names = {t.name for t in asyncio.run(srv.server.list_tools())}
    assert names == {"proxy_url", "check_proxy", "list_locations", "account_status",
                     "traffic_stats", "top_domains", "list_sub_users"}


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
    assert fake.calls[-1] == ("countries", {"connection_type": "residential", "limit": "100"})


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


def test_every_tool_is_marked_read_only():
    tools = asyncio.run(srv.server.list_tools())
    assert all(t.annotations and t.annotations.read_only_hint for t in tools)
