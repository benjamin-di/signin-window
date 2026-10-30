"""Escaping and the exact-script CSP boundary for shared connection screens."""

import base64
import hashlib
import re

from signin_window.connections import SCRIPT_SOURCE, disconnect_confirmation, page, timestamp


def test_account_text_is_not_treated_as_markup_and_csp_only_permits_the_fixed_script():
    rendered = page('<img src=x onerror="bad()">', "<article>Trusted markup</article>", intro="<Account>", refresh=True)
    assert '<img src=x onerror="bad()">' not in rendered
    assert "&lt;Account&gt;" in rendered and "<article>Trusted markup</article>" in rendered
    script = re.search(r"<script>(.*?)</script>", rendered, re.S).group(1)
    digest = base64.b64encode(hashlib.sha256(script.encode()).digest()).decode()
    assert SCRIPT_SOURCE == f"'sha256-{digest}'"
    assert "data-refresh" in rendered and "<noscript>" in rendered
    assert "data-refresh" not in page("Example", "<p>Saved</p>").split("<script>")[0]


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
