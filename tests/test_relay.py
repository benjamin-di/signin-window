"""Sign-in links: open without a bearer but only with the link's id, single use and short-lived, one per key; the
window's end runs the consumer's hook, whose state the link takes; the session never leaves the hook."""

from __future__ import annotations

import pytest
from starlette.applications import Starlette
from starlette.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from signin_window import relay as relay_module
from signin_window.client import LoginBusy, LoginUnavailable
from signin_window.page import PageText
from signin_window.relay import Link, LinkLimited, Relay

VNC_HTML = b"<!doctype html><html><head><script type=module>import UI from './app/ui.js';</script></head></html>"
SESSION = {"cookies": [{"name": "sid", "value": "s3cret-cookie"}]}


class FakeBackend:
    """The login service: every window waits for the person until a test ends it."""

    def __init__(self) -> None:
        self.started: list[tuple[str, dict]] = []
        self.closed: list[str] = []
        self.states: dict[str, dict] = {}
        self.results: dict[str, dict] = {}
        self.busy = False
        self.down = False

    def start(self, layout: str = "desktop", **params) -> dict:
        if self.down:
            raise LoginUnavailable("down")
        if self.busy:
            raise LoginBusy("busy")
        window_id = f"window-{len(self.started):010d}"
        self.started.append((layout, params))
        self.states[window_id] = {"state": "waiting", "host": "accounts.example.com"}
        return {"id": window_id, "state": "starting", "view_token": "v" * 24}

    def state(self, window_id: str) -> dict:
        return self.states.get(window_id, {"state": "unknown"})

    def result(self, window_id: str) -> dict | None:
        return self.results.pop(window_id, None)

    def close(self, window_id: str) -> None:
        self.closed.append(window_id)
        if self.states.get(window_id, {}).get("state") == "waiting":
            self.states[window_id] = {"state": "cancelled"}

    def static(self, path: str) -> tuple[int, bytes, str]:
        if path == "vnc.html":
            return 200, VNC_HTML, "text/html"
        if path == "core/rfb.js":
            return 200, b"export default class RFB {}", "text/javascript"
        return 404, b"", "text/plain"

    async def bridge(self, window_id: str, view_token: str, ws) -> None:
        await ws.send_bytes(b"RFB 003.008\n")

    def hand_over(self, window_id: str, session: dict | None = None) -> None:
        self.states[window_id] = {"state": "signed_in", "host": "www.example.com"}
        self.results[window_id] = session or SESSION

    def end(self, window_id: str, state: str) -> None:
        self.states[window_id] = {"state": state, "host": "www.example.com"}


class Clock:
    now = 1_000_000.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def backend() -> FakeBackend:
    return FakeBackend()


@pytest.fixture
def stored() -> dict:
    return {}


@pytest.fixture
def clock() -> Clock:
    return Clock()


def make_relay(backend, stored, clock, **kwargs) -> Relay:
    def on_signed_in(link: Link, session: dict) -> str:
        if session.get("cookies", [{}])[0].get("value") == "someone-else":
            return "wrong_account"
        stored[link.key] = session
        link.show(name="J. Doe")
        return "connected"

    text = PageText(service="Example", secure_host=r"(^|\.)example\.com$").with_outcomes(
        connected="<h1>Connected as {name}</h1>", wrong_account="<h1>That is another account</h1>"
    )
    kwargs.setdefault("on_signed_in", on_signed_in)
    return Relay(backend, "https://mcp.example.com/connect", text=text, clock=clock, **kwargs)


@pytest.fixture
def relay(backend, stored, clock) -> Relay:
    return make_relay(backend, stored, clock)


@pytest.fixture
def http(relay) -> TestClient:
    return TestClient(Starlette(routes=relay.routes("/connect")))


def path(link: Link) -> str:
    return link.url.removeprefix("https://mcp.example.com")


def start(http, link: Link, layout: str = "desktop") -> dict:
    return http.post(path(link) + "/start", json={"layout": layout}).json()


def state(http, link: Link) -> dict:
    return http.get(path(link) + "/state").json()


def test_a_link_is_an_unguessable_url_under_the_public_url(relay):
    link = relay.create("alice", label="alice@example.com")
    assert link.url.startswith("https://mcp.example.com/connect/") and len(link.id) == 32
    assert link.key == "alice" and link.label == "alice@example.com" and link.expires_at.endswith("+00:00")


def test_the_public_url_must_be_plain_http(backend):
    for bad in ("ftp://example.com", "https://example.com/x?y=1", "example.com"):
        with pytest.raises(ValueError):
            Relay(backend, bad)


def test_the_page_needs_no_bearer_and_is_never_cached_framed_or_referred(relay, http):
    link = relay.create("alice", label="<alice>")
    page = http.get(path(link))
    assert page.status_code == 200
    assert page.headers["cache-control"] == "no-store" and page.headers["x-frame-options"] == "DENY"
    assert (
        page.headers["referrer-policy"] == "no-referrer"
        and "frame-ancestors 'none'" in page.headers["content-security-policy"]
    )
    assert "&lt;alice&gt;" in page.text and "<alice>" not in page.text
    assert "Connect your Example account" in page.text and "Connected as {name}" in page.text


@pytest.mark.parametrize("suffix", ["", "/state", "/novnc/vnc.html"])
def test_an_unknown_link_is_the_expired_page(http, suffix):
    response = http.get("/connect/" + "x" * 32 + suffix)
    assert response.status_code == 404
    if not suffix:
        assert "This link has expired" in response.text


def test_guessing_ids_is_slowed_but_never_locks_out_a_real_link(relay, http):
    link = relay.create("alice")
    for _ in range(relay_module.MISSES_PER_ADDRESS):
        http.get("/connect/" + "y" * 32 + "/state", headers={"X-Forwarded-For": "203.0.113.9"})
    assert http.get("/connect/" + "y" * 32 + "/state", headers={"X-Forwarded-For": "203.0.113.9"}).status_code == 429
    assert http.get(path(link) + "/state", headers={"X-Forwarded-For": "203.0.113.9"}).status_code == 200


def test_a_new_link_replaces_the_old_one_and_closes_its_window(relay, http, backend):
    old = relay.create("alice")
    start(http, old)
    new = relay.create("alice")
    other = relay.create("bob")
    assert old.closed and not new.closed and not other.closed
    assert relay.links("alice") == [new]
    for _ in range(100):
        if backend.closed:
            break
        import time

        time.sleep(0.01)
    assert backend.closed == ["window-0000000000"]
    assert http.get(path(old)).status_code == 404


def test_links_are_rate_limited_per_key(relay):
    for _ in range(relay.links_per_hour):
        relay.create("alice")
    with pytest.raises(LinkLimited):
        relay.create("alice")
    relay.create("bob")


def test_the_link_expires(relay, http, clock):
    link = relay.create("alice")
    clock.now += relay.link_ttl + 1
    assert http.get(path(link)).status_code == 404 and link.closed


def test_start_sends_the_links_params_and_the_layout(relay, http, backend):
    link = relay.create("example.de", params={"site": "example.de"})
    assert start(http, link, "phone")["state"] == "starting"
    assert backend.started == [("phone", {"site": "example.de"})]
    assert start(http, link)["state"] == "starting"  # an open window is not opened twice
    assert len(backend.started) == 1


def test_a_handed_over_session_goes_to_the_hook_and_never_to_the_page(relay, http, backend, stored):
    link = relay.create("alice")
    start(http, link)
    assert state(http, link) == {"state": "waiting", "host": "accounts.example.com"}
    backend.hand_over("window-0000000000")
    body = state(http, link)
    assert body == {"state": "connected", "host": "www.example.com", "name": "J. Doe"}
    assert stored == {"alice": SESSION}
    assert "s3cret" not in http.get(path(link) + "/state").text
    assert http.get(path(link)).status_code == 404  # a connected link opens nothing more
    assert start(http, link)["state"] == "connected" and len(backend.started) == 1


def test_the_hook_can_refuse_with_a_state_of_its_own(relay, http, backend, stored):
    link = relay.create("alice")
    start(http, link)
    backend.hand_over("window-0000000000", {"cookies": [{"name": "sid", "value": "someone-else"}]})
    assert state(http, link)["state"] == "wrong_account" and stored == {}
    assert start(http, link)["state"] == "starting"  # try again


@pytest.mark.parametrize("outcome", ["no_such_state", "expired", "limited"])
def test_a_hook_state_the_page_has_no_message_for_is_failed(backend, stored, clock, outcome):
    relay = make_relay(backend, stored, clock, on_signed_in=lambda link, session: outcome)
    http = TestClient(Starlette(routes=relay.routes("/connect")))
    link = relay.create("alice")
    start(http, link)
    backend.hand_over("window-0000000000")
    assert state(http, link)["state"] == "failed"


def test_a_failing_hook_is_failed(backend, stored, clock):
    def broken(link, session):
        raise OSError("disk full")

    relay = make_relay(backend, stored, clock, on_signed_in=broken)
    http = TestClient(Starlette(routes=relay.routes("/connect")))
    link = relay.create("alice")
    start(http, link)
    backend.hand_over("window-0000000000")
    assert state(http, link)["state"] == "failed"


def test_without_a_hook_a_hand_over_fails(backend, clock):
    relay = Relay(backend, "https://mcp.example.com/connect", clock=clock)
    http = TestClient(Starlette(routes=relay.routes("/connect")))
    link = relay.create("alice")
    start(http, link)
    backend.hand_over("window-0000000000")
    assert state(http, link)["state"] == "failed"


def test_a_window_that_kept_its_session_reports_its_own_end(relay, http, backend):
    link = relay.create("alice")
    start(http, link)
    backend.end("window-0000000000", "connected")
    assert state(http, link)["state"] == "connected"
    other = relay.create("bob")
    start(http, other)
    backend.end("window-0000000001", "wrong_account")
    assert state(http, other)["state"] == "wrong_account"


@pytest.mark.parametrize("window_state", ["expired", "unknown", "closed", "signed_out"])
def test_other_window_ends_are_failed(relay, http, backend, window_state):
    link = relay.create("alice")
    start(http, link)
    backend.end("window-0000000000", window_state)
    assert state(http, link)["state"] == "failed"


def test_on_ended_decides_a_kept_sessions_end(backend, stored, clock):
    seen = []

    def on_ended(link, window):
        seen.append(window["state"])
        return "connected" if window.get("account") == "jane@example.com" else "failed"

    relay = make_relay(backend, stored, clock, on_ended=on_ended)
    http = TestClient(Starlette(routes=relay.routes("/connect")))
    link = relay.create("alice")
    start(http, link)
    backend.states["window-0000000000"] = {"state": "connected", "account": "jane@example.com"}
    assert state(http, link)["state"] == "connected" and seen == ["connected"]


def test_busy_unavailable_cancel_and_the_start_limit(relay, http, backend):
    link = relay.create("alice")
    backend.busy = True
    assert start(http, link)["state"] == "busy"
    backend.busy, backend.down = False, True
    assert start(http, link)["state"] == "failed"
    backend.down = False
    assert start(http, link)["state"] == "starting"
    assert http.post(path(link) + "/cancel").status_code == 204
    assert state(http, link)["state"] == "cancelled" and backend.closed == ["window-0000000000"]
    assert start(http, link)["state"] == "starting"  # the fourth start
    http.post(path(link) + "/cancel")
    assert start(http, link)["state"] == "cancelled"  # no fifth
    assert http.get(path(link)).status_code == 404


def test_the_viewer_is_novnc_plus_the_paste_add_on(relay, http):
    link = relay.create("alice")
    viewer = http.get(path(link) + "/novnc/vnc.html")
    assert viewer.status_code == 200 and b'<script type="module" src="paste.js"></script>' in viewer.content
    assert viewer.headers["x-frame-options"] == "SAMEORIGIN"
    paste = http.get(path(link) + "/novnc/paste.js")
    assert paste.status_code == 200 and paste.headers["content-type"].startswith("text/javascript")
    assert http.get(path(link) + "/novnc/core/rfb.js").status_code == 200
    assert http.get(path(link) + "/novnc/missing.js").status_code == 404


def test_the_live_view_needs_a_window_showing_its_sign_in_page(relay, http):
    link = relay.create("alice")
    with pytest.raises(WebSocketDisconnect), http.websocket_connect(path(link) + "/vnc"):
        pass
    start(http, link)
    state(http, link)
    with http.websocket_connect(path(link) + "/vnc") as ws:
        assert ws.receive_bytes() == b"RFB 003.008\n"


def test_the_app_serves_the_routes_at_its_root(backend, stored, clock):
    relay = make_relay(backend, stored, clock)
    link = relay.create("alice")
    http = TestClient(relay.app())
    assert http.get("/" + link.id).status_code == 200


def test_a_shown_field_cannot_replace_the_state():
    link = Link("x" * 32, "k", 0.0, 1.0, "https://example.com/x")
    link.show(state="connected", host="evil", name="J" * 300, **{"Bad-Name": "x"})
    assert link.public() == {"name": "J" * 100, "state": "ready", "host": ""}


def test_before_start_can_refuse_a_window_or_add_to_its_params(backend, stored, clock):
    allowed = {"ok": False}

    def before_start(link):
        if not allowed["ok"]:
            return "invite_required"
        link.params["account"] = "jane"
        return None

    text = PageText().with_outcomes(invite_required="<h1>Enter your invite code</h1>")
    relay = Relay(backend, "https://mcp.example.com/connect", text=text, before_start=before_start, clock=clock)
    http = TestClient(Starlette(routes=relay.routes("/connect")))
    link = relay.create("pending")
    assert start(http, link)["state"] == "invite_required" and backend.started == []
    allowed["ok"] = True
    assert start(http, link)["state"] == "starting"
    assert backend.started == [("desktop", {"account": "jane"})]


def test_a_saving_window_is_followed_and_not_cancelled(relay, http, backend):
    link = relay.create("alice")
    start(http, link)
    backend.states["window-0000000000"] = {"state": "saving", "host": "www.example.com"}
    assert state(http, link)["state"] == "saving"
    http.post(path(link) + "/cancel")
    assert backend.closed == [] and state(http, link)["state"] == "saving"
    backend.end("window-0000000000", "connected")
    assert state(http, link)["state"] == "connected"
