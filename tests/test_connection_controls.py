"""Durable application pause and escaped opt-in Connections controls."""

import json
import stat
from concurrent.futures import ThreadPoolExecutor

import pytest

from signin_window.connection_state import (
    ConnectionActivity,
    ConnectionControls,
    ConnectionPaused,
    ConnectionStatus,
)
from signin_window.connections import controls_panel, page
from signin_window.state import PrivateStateError

AT = "2026-01-01T12:00:00+00:00"


def test_application_worker_checks_durable_pause_after_restart_and_activity_preserves_it(tmp_path):
    root = tmp_path / "owner-a" / "example-app"
    controls = ConnectionControls(root)
    controls.require_active()
    controls.set_paused(True)
    restarted = ConnectionControls(root)
    with pytest.raises(ConnectionPaused):
        restarted.require_active()
    restarted.record_activity(ConnectionActivity("Previous run finished", occurred_at=AT))
    with pytest.raises(ConnectionPaused):
        controls.require_active()
    restarted.set_paused(False)
    controls.require_active()
    assert controls.snapshot().activity[0].summary == "Previous run finished"
    assert stat.S_IMODE((root / "controls.json").stat().st_mode) == 0o600
    assert stat.S_IMODE(root.stat().st_mode) == 0o700
    # A distinct owner is unaffected; roots come from authenticated application identity.
    ConnectionControls(tmp_path / "owner-b" / "example-app").require_active()


def test_concurrent_application_updates_keep_pause_and_bounded_recent_activity(tmp_path):
    controls = ConnectionControls(tmp_path, max_activity=3)
    controls.set_paused(True)
    with ThreadPoolExecutor(max_workers=4) as workers:
        list(workers.map(lambda i: controls.record_activity(ConnectionActivity(str(i), occurred_at=AT)), range(10)))
    state = controls.snapshot()
    assert state.paused
    assert len(state.activity) == 3
    assert len({item.summary for item in state.activity}) == 3


@pytest.mark.parametrize(
    "payload",
    [
        b"not JSON",
        b"{}",
        b'{"version":1,"paused":0,"activity":[]}',
        b'{"version":1,"paused":false,"activity":[{"summary":"x","occurred_at":"bad"}]}',
    ],
)
def test_corrupt_state_never_enables_application_work(tmp_path, payload):
    (tmp_path / "controls.json").write_bytes(payload)
    with pytest.raises(PrivateStateError):
        ConnectionControls(tmp_path).require_active()


def test_symlinked_private_state_is_refused(tmp_path):
    other = tmp_path / "unrelated.json"
    original = json.dumps({"version": 1, "paused": False, "activity": []})
    other.write_text(original)
    root = tmp_path / "controls"
    root.mkdir()
    (root / "controls.json").symlink_to(other)
    controls = ConnectionControls(root)
    with pytest.raises(PrivateStateError):
        controls.require_active()
    with pytest.raises(PrivateStateError):
        controls.set_paused(True)
    assert other.read_text() == original
    alias = tmp_path / "alias"
    alias.symlink_to(root, target_is_directory=True)
    with pytest.raises(PrivateStateError):
        ConnectionControls(alias)


def test_opt_in_panel_escapes_values_and_preserves_the_applications_action_form():
    activity = ConnectionActivity(
        '<img src=x onerror="bad()">',
        "<script>bad()</script>",
        url="https://app.example/result?a=1&b=2",
        occurred_at=AT,
    )
    form = '<form method="post" action="/connections/pause"><input name="csrf" value="example"></form>'
    rendered = controls_panel(
        ConnectionStatus(paused=True, activity=(activity,)), granted_scopes=["<read&write>"], pause_form=form
    )
    assert form in rendered
    assert "&lt;img" in rendered and "&lt;script&gt;" in rendered
    assert "<script>" not in rendered and "<img" not in rendered
    assert '<a href="https://app.example/result?a=1&amp;b=2">' in rendered
    assert "&lt;read&amp;write&gt;" in rendered and "1 Jan 2026 at 12:00 UTC" in rendered
    assert 'role="status">Paused</p>' in rendered
    unchanged = page("Example", "<article>Existing content</article>")
    assert 'aria-label="Connection controls"' not in unchanged


@pytest.mark.parametrize(
    "target",
    [
        "javascript:alert(1)",
        "data:text/html,example",
        "http://app.example",
        "//other.example/path",
        "/\\other.example",
        "/\t/other.example",
        "https://user:pw@example.com/",
        "https://app.example:99999",
        "https://[invalid",
    ],
)
def test_unsafe_activity_links_render_as_plain_text(target):
    activity = ConnectionActivity("Draft result", url=target, occurred_at=AT)
    rendered = controls_panel(ConnectionStatus(activity=(activity,)))
    assert "Draft result" in rendered and "<a href=" not in rendered


def test_root_relative_link_and_optional_scopes():
    rendered = controls_panel(
        ConnectionStatus(activity=(ConnectionActivity("Result", url="/results/42", occurred_at=AT),))
    )
    assert '<a href="/results/42">Result</a>' in rendered
    assert "Granted access" not in rendered
    assert "No scopes granted" in controls_panel(ConnectionStatus(), granted_scopes=[])
    assert "No activity recorded" in controls_panel(ConnectionStatus())


def test_activity_requires_a_timezone_and_pause_rejects_truthy_strings(tmp_path):
    with pytest.raises(ValueError):
        ConnectionActivity("Example", occurred_at="2026-01-01T12:00:00")
    with pytest.raises(ValueError):
        ConnectionControls(tmp_path).set_paused("false")
