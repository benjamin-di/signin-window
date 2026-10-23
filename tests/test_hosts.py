"""Keeping a window on the site: the route check and Chromium's resolver rules."""

from __future__ import annotations

from signin_window.hosts import allowed, host_matches, host_resolver_rules, proxy_hosts

SITE = ("example.com", "login.example.net")


def test_a_host_matches_itself_and_its_subdomains_only():
    assert host_matches("example.com", "example.com") and host_matches("WWW.Example.com.", "example.com")
    assert not host_matches("evilexample.com", "example.com") and not host_matches("example.com.evil", "example.com")
    assert not host_matches("example.com", "")


def test_only_https_on_the_sites_hosts_is_allowed():
    assert allowed("https://www.example.com/signin", SITE)
    assert allowed("https://login.example.net/", SITE)
    assert not allowed("http://www.example.com/", SITE)
    assert not allowed("https://example.net/", SITE)
    assert not allowed("https://user:pw@example.com/", SITE)
    assert not allowed("javascript:alert(1)", SITE) and not allowed("data:text/html,x", SITE)
    assert allowed("http://localhost:8080/", ("localhost",), schemes=("http", "https"))


def test_every_other_host_resolves_to_nothing_but_the_proxy():
    rules = host_resolver_rules(["Example.com", ".cdn.example.net", ""], proxies=["proxy.example"])
    assert rules == (
        "MAP * ~NOTFOUND, EXCLUDE example.com, EXCLUDE *.example.com, EXCLUDE cdn.example.net, "
        "EXCLUDE *.cdn.example.net, EXCLUDE proxy.example"
    )


def test_proxy_hosts_come_from_the_environment():
    env = {"HTTPS_PROXY": "http://proxy.example:3128", "http_proxy": "proxy.example:3128", "ALL_PROXY": ""}
    assert proxy_hosts(env) == ["proxy.example"]
    assert proxy_hosts({}) == []
