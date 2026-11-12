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
