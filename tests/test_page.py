"""The link's page: the consumer's text, escaped where it comes from a link, and a configuration that cannot end
its script element."""

from __future__ import annotations

import json
import re

from signin_window.page import DEFAULT_OUTCOMES, PageText, render


def config(page: str) -> dict:
    return json.loads(re.search(r"const CONFIG = (.*?);</script>", page, re.S).group(1))


def test_the_service_and_label_fill_the_text_escaped():
    text = PageText(service="Shop & Co", intro_html="For <b>{label}</b> at {service}.")
    page = render(text, '<img src=x onerror="alert(1)">')
    assert "For <b>&lt;img src=x onerror=&quot;alert(1)&quot;&gt;</b> at Shop &amp; Co." in page
    assert "<title>Connect your Shop &amp; Co account</title>" in page


def test_outcomes_carry_the_consumers_states_and_no_script_can_be_closed_early():
    text = PageText().with_outcomes(wrong_account="<h1>Other account</h1></script><script>alert(1)</script>")
    page = render(text, "jane")
    assert "</script><script>alert(1)" not in page.split("const CONFIG = ")[1].split(";</script>")[0]
    outcomes = config(page)["outcomes"]
    assert outcomes["wrong_account"].startswith("<h1>Other account</h1>")
    assert set(DEFAULT_OUTCOMES) <= set(outcomes)
    assert config(page)["noRetry"] == ["connected", "expired", "limited"]


def test_the_expired_page_has_no_script():
    page = render(PageText(), None)
    assert "This link has expired" in page and "<script" not in page


def test_expired_hosted_link_returns_to_connections_without_starting_an_attempt():
    page = render(PageText(return_url="/application/connections/"), None)
    assert 'href="/application/connections/"' in page and "Back to Connections" in page
    assert "<script" not in page and "<form" not in page


def test_extra_script_comes_before_the_page_script():
    page = render(PageText(script_extra="window.signinBeforeStart = async () => true;"), "jane")
    assert page.index("window.signinBeforeStart = async") < page.index("const CONFIG")


def test_the_label_fills_the_title_host_and_button_too():
    text = PageText(service="Shop", title="Sign in to {label}", host_label="{label}", button="Continue on {label}")
    page = render(text, "shop.example<")
    assert "<title>Sign in to shop.example&lt;</title>" in page and "<h1>Sign in to shop.example&lt;</h1>" in page
    assert "<span id=host>shop.example&lt;</span>" in page and ">Continue on shop.example&lt;</button>" in page
    assert config(page)["frameTitle"] == "Sign in to shop.example<"
    assert "<title>Sign in to</title>" in render(text, None)
