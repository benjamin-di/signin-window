"""Keeping a window on the site: the route check and Chromium's resolver rules."""

from __future__ import annotations

from types import SimpleNamespace

from signin_window.hosts import allowed, host_matches, host_resolver_rules, proxy_hosts, top_level

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


class Request:
    def __init__(self, navigation: bool, parent: object = None, popup: bool = False) -> None:
        self.navigation, self.parent, self.popup = navigation, parent, popup

    def is_navigation_request(self) -> bool:
        return self.navigation

    @property
    def frame(self):
        if self.popup:  # what Playwright does for a popup's first navigation
            raise RuntimeError("Frame for this navigation request is not available")
        return SimpleNamespace(parent_frame=self.parent)


def test_top_level_is_a_page_document_including_a_popups_first_page():
    assert top_level(Request(navigation=True))
    assert top_level(Request(navigation=True, popup=True))
    assert not top_level(Request(navigation=True, parent=object()))  # a frame inside the page
    assert not top_level(Request(navigation=False))  # a script, image or fetch
