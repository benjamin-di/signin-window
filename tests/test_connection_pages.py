"""Escaping and the exact-script CSP boundary for shared connection screens."""

import base64
import hashlib
import re
from dataclasses import FrozenInstanceError
from html.parser import HTMLParser

import pytest

from signin_window.connections import SCRIPT_SOURCE, PageIdentity, disconnect_confirmation, page, timestamp


class IdentityFooter(HTMLParser):
    def __init__(self, rendered):
        super().__init__()
        self.attributes = {}
        self.text = ""
        self.in_footer = False
        self.feed(rendered)

    def handle_starttag(self, tag, attrs):
        if tag == "footer":
            self.in_footer = True
            self.attributes = dict(attrs)

    def handle_data(self, data):
        if self.in_footer:
            self.text += data

    def handle_endtag(self, tag):
        if tag == "footer":
            self.in_footer = False


def test_account_text_is_not_treated_as_markup_and_csp_only_permits_the_fixed_script():
    rendered = page('<img src=x onerror="bad()">', "<article>Trusted markup</article>", intro="<Account>", refresh=True)
    assert '<img src=x onerror="bad()">' not in rendered
    assert "&lt;Account&gt;" in rendered and "<article>Trusted markup</article>" in rendered
    script = re.search(r"<script>(.*?)</script>", rendered, re.S).group(1)
    digest = base64.b64encode(hashlib.sha256(script.encode()).digest()).decode()
    assert SCRIPT_SOURCE == f"'sha256-{digest}'"
    assert "data-refresh" in rendered and "<noscript>" in rendered
    assert "data-refresh" not in page("Example", "<p>Saved</p>").split("<script>")[0]


def test_host_identity_is_immutable_escaped_and_keeps_the_full_revision_accessible():
    identity = PageIdentity('<img src=x onerror="bad()">', '1.2.3" <dev>', 'abcdef1234567890" <revision>')
    with pytest.raises(FrozenInstanceError):
        identity.version = "changed"
    rendered = page("Example", "<p>Saved</p>", identity=identity)
    footer = IdentityFooter(rendered)
    assert footer.text == (
        f"{identity.service} v{identity.version} · abcdef123456Source revision{identity.source_revision}"
    )
    assert footer.attributes == {
        "id": "connection-identity",
        "data-service": identity.service,
        "data-version": identity.version,
        "data-source-revision": identity.source_revision,
        "title": f"Source revision: {identity.source_revision}",
    }
    assert '<img src=x onerror="bad()">' not in rendered
    assert "&lt;revision&gt;" in rendered
    assert "<a " not in rendered.split("<script>")[0]


def test_omitted_identity_preserves_existing_pages_and_empty_metadata_is_explicit():
    assert not IdentityFooter(page("Example", "<p>Saved</p>")).attributes
    footer = IdentityFooter(page("Example", "<p>Saved</p>", identity=PageIdentity(" ", "", "")))
    assert footer.text == "unknown vdev · unknownSource revisionunknown"
    assert footer.attributes["data-source-revision"] == "unknown"


def test_script_csp_hash_also_matches_a_page_with_build_identity():
    rendered = page("Example", "", identity=PageIdentity("Example", "1.2.3", "abcdef1234567890"))
    script = re.search(r"<script>(.*?)</script>", rendered, re.S).group(1)
    digest = base64.b64encode(hashlib.sha256(script.encode()).digest()).decode()
    assert SCRIPT_SOURCE == f"'sha256-{digest}'"


def test_disconnect_explains_effect_without_changing_the_applications_form():
    form = '<form method="post" action="/connections/disconnect"><input name="revision" value="safe"></form>'
    result = disconnect_confirmation(form, "Shop & Co", "Stop this application's access; keep your data.")
    assert "<summary>Disconnect Shop &amp; Co…</summary>" in result
    assert form in result and result.index("<summary>") < result.index(form)


def test_timestamps_are_readable_and_missing_facts_are_not_invented():
    assert "30 Oct 2026 at 09:04 UTC" in timestamp("2026-10-30T11:04:00+02:00")
    assert "not recorded" in timestamp(None)
    assert "not recorded" in timestamp("not-a-date")
    assert "not recorded" in timestamp(float("inf"))


@pytest.mark.parametrize(
    "origin",
    [
        "https://id.example.com",
        "https://id.example.com:8443",
        "https://id--prod.example",
        "https://xn--strae-oqa.example",
        "https://[2001:db8::1]",
    ],
)
def test_page_emits_preconnect_link_in_head_for_clean_https_origin(origin):
    without = page("Example", "<p>Saved</p>")
    assert 'rel="preconnect"' not in without
    rendered = page("Example", "<p>Saved</p>", preconnect=origin)
    head = rendered.split("</head>", 1)[0]
    assert f'<link rel="preconnect" href="{origin}" crossorigin>' in head
    script = re.search(r"<script>(.*?)</script>", rendered, re.S).group(1)
    digest = base64.b64encode(hashlib.sha256(script.encode()).digest()).decode()
    assert SCRIPT_SOURCE == f"'sha256-{digest}'"


_HTTPS = "https://"


@pytest.mark.parametrize(
    "invalid",
    [
        "",
        "http://id.example.com",
        "HTTPS://id.example.com",
        _HTTPS,
        "https://id.example.com/",
        "https://id.example.com/auth",
        f"{_HTTPS}id.example.com?a=1",
        f"{_HTTPS}id.example.com?",
        f"{_HTTPS}id.example.com#frag",
        f"{_HTTPS}id.example.com#",
        f"{_HTTPS}user:pass@id.example.com",
        "https://@id.example.com",
        "https://id.example.com ",
        " https://id.example.com",
        "https://id.example.com\n",
        "https://id.example.com:99999",
        "https://id.example.com\\path",
        "https://id.example.com|invalid",
        f"{_HTTPS}id.example.com%zz",
        "https://-bad.example.com",
        "https://bad..example.com",
        f"{_HTTPS}999.999.999.999",
        f"{_HTTPS}id.example.0x1",
        f"{_HTTPS}id.example.0Xff",
        "https://xn--a.example",
        "https://xn--a-wbb.example",
        "https://[v1.example]",
        "https://[2001:db8::1]junk:443",
        "https://[fe80::1%demo]",
        "javascript:alert(1)",
    ],
)
def test_page_rejects_invalid_preconnect_origins(invalid):
    with pytest.raises(ValueError):
        page("Example", "<p>Saved</p>", preconnect=invalid)


def _directory():
    from signin_window.connections import SuiteDirectory

    return SuiteDirectory.from_json(
        '{"name": "Example <Suite>", "apps": ['
        '{"label": "Shop", "url": "https://shop.example.com/connections/", "section": "Accounts",'
        ' "description": "Orders & <basket>", "groups": ["shop-users"]},'
        '{"label": "Ledger", "url": "https://ledger.example.com/", "groups": ["ledger-users", "auditors"]},'
        '{"label": "Help", "url": "https://help.example.com/"}]}'
    )


def test_suite_shows_only_links_for_the_visitors_groups_and_marks_the_current_application():
    suite = _directory().suite(
        groups=["auditors"], current="https://SHOP.example.com/connections/status", account="<Alex>"
    )
    assert [(link.label, link.current) for link in suite.links] == [("Shop", True), ("Ledger", False), ("Help", False)]
    assert [link.label for link in _directory().suite(groups=[]).links] == ["Help"]
    rendered = page("Shop accounts", "<p>Saved</p>", suite=suite)
    head, shell = rendered.split("<script>")[0].split("<body>")
    assert "<title>Shop accounts · Example &lt;Suite&gt;</title>" in head
    assert '<a class="suite-brand" href="https://shop.example.com/connections/">' in shell
    assert '<a href="https://shop.example.com/connections/" aria-current="page">' in shell
    assert '<a href="https://ledger.example.com/">' in shell and "<h2>Accounts</h2>" in shell
    assert "Orders &amp; &lt;basket&gt;" in shell and "&lt;Alex&gt;" in shell and "<Alex>" not in shell
    assert 'class="eyebrow"' not in shell and shell.index("</header>") < shell.index("<main>")
    assert "style=" not in shell
    script = re.search(r"<script>(.*?)</script>", rendered, re.S).group(1)
    assert SCRIPT_SOURCE == "'sha256-" + base64.b64encode(hashlib.sha256(script.encode()).digest()).decode() + "'"


def test_suite_without_siblings_has_no_switcher_and_plain_pages_keep_their_heading():
    alone = _directory().suite(groups=[], current="https://shop.example.com")
    assert [link.label for link in alone.links] == ["Shop", "Help"]
    from signin_window.connections import Suite, SuiteLink

    only = page(
        "Shop", "<p>Saved</p>", suite=Suite("Suite", (SuiteLink("Shop", "https://shop.example.com/", current=True),))
    )
    assert "suite-switch" not in only.split("<style>")[1].split("</style>")[1].split("<script>")[0]
    plain = page("Example", "<p>Saved</p>").split("<script>")[0]
    assert '<p class="eyebrow">Connections</p><h1>Example</h1>' in plain and "<nav" not in plain


@pytest.mark.parametrize(
    "text",
    [
        "not json",
        "[]",
        '{"name": "", "apps": []}',
        '{"name": "Suite", "apps": [{"label": "Shop", "url": "http://shop.example.com/"}]}',
        '{"name": "Suite", "apps": [{"label": "Shop", "url": "javascript:alert(1)"}]}',
        '{"name": "Suite", "apps": [{"label": "Shop", "url": "https://user@shop.example.com/"}]}',
        '{"name": "Suite", "apps": [{"label": "Shop", "url": "https://shop.example.com/ x"}]}',
        '{"name": "Suite", "apps": [{"label": "Shop", "url": "https://shop.example.com/", "groups": "all"}]}',
        '{"name": "Suite", "apps": [{"label": "Shop", "url": "https://shop.example.com/", "extra": 1}]}',
        '{"name": "Suite", "apps": [{"label": "A", "url": "https://a.example.com/"},'
        ' {"label": "B", "url": "https://a.example.com/"}]}',
    ],
)
def test_suite_directory_rejects_malformed_configuration(text):
    from signin_window.connections import SuiteDirectory

    with pytest.raises(ValueError):
        SuiteDirectory.from_json(text)


@pytest.mark.parametrize("current", [True, False])
def test_a_hand_built_suite_link_cannot_carry_an_executable_url(current):
    from signin_window.connections import SuiteEndpoint, SuiteLink

    with pytest.raises(ValueError):
        SuiteLink("Bad", "javascript:alert(1)", current=current)
    with pytest.raises(ValueError):
        SuiteEndpoint("Address", "javascript:alert(1)")


@pytest.mark.parametrize(
    "url",
    [
        "HTTPS://shop.example.com/",
        "https://shop.example.com/#",
        "https://shop.example.com:/",
        "https://shop.example.com:0443/",
        "https://shop.example.com/\u00a0",
        "https://shop.example.com/\u0085",
        "https://shop.example.com\\@evil.example.com/",
        "//shop.example.com/",
    ],
)
def test_suite_urls_are_as_strict_as_other_page_origins(url):
    from signin_window.connections import SuiteLink

    with pytest.raises(ValueError):
        SuiteLink("Shop", url)


def test_the_endpoint_appears_only_on_applications_that_opt_in_and_is_escaped():
    from signin_window.connections import SuiteDirectory

    text = (
        '{"name": "Suite", "endpoint": {"title": "Use with <assistant>", "url": "https://tools.example.com/all",'
        ' "help": "Add this address & sign in."}, "apps": ['
        '{"label": "Shop", "url": "https://shop.example.com/", "endpoint": true},'
        '{"label": "Help", "url": "https://help.example.com/"}]}'
    )
    directory = SuiteDirectory.from_json(text)
    shop = page("Shop", "<p>Saved</p>", suite=directory.suite(groups=[], current="https://shop.example.com"))
    assert "<summary>Use with &lt;assistant&gt;</summary><p>Add this address &amp; sign in.</p>" in shop
    assert '<code id="connection-suite-endpoint">https://tools.example.com/all</code>' in shop
    assert 'data-copy-code="connection-suite-endpoint" data-copied="Address copied"' in shop
    help_page = page("Help", "<p>Saved</p>", suite=directory.suite(groups=[], current="https://help.example.com"))
    assert 'id="connection-suite-endpoint"' not in help_page
    with pytest.raises(ValueError):
        SuiteDirectory.from_json(text.replace('"endpoint": {"title"', '"other": {"title"'))
    with pytest.raises(ValueError):
        SuiteDirectory.from_json(
            '{"name": "S", "apps": [{"label": "A", "url": "https://a.example.com/", "endpoint": true}]}'
        )


def test_the_switcher_keeps_an_accessible_name_when_its_label_is_visually_hidden():
    rendered = page("Shop", "<p>Saved</p>", suite=_directory().suite(groups=[], current="https://shop.example.com"))
    assert '<summary aria-label="Apps">' in rendered


def test_badge_escapes_its_text_and_accepts_only_known_tones():
    from signin_window.connections import badge

    assert badge("<Ready>", "ok") == '<span class="badge ok">&lt;Ready&gt;</span>'
    assert badge("Idle") == '<span class="badge">Idle</span>'
    with pytest.raises(ValueError):
        badge("x", 'ok" onclick="bad()')
