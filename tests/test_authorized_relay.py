"""Host authentication covers every attempt route and existing viewer streams."""

import threading

import pytest
from starlette.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from signin_window.page import PageText
from signin_window.relay import AttemptContext, Relay


class Backend:
    def __init__(self):
        self.started = []
        self.closed = []
        self.released = threading.Event()

    def start(self, layout="desktop", **params):
        self.started.append(params)
        return {"id": "window", "view_token": "private-view-token"}

    def state(self, window_id):
        return {"state": "waiting"}

    def close(self, window_id):
        self.closed.append(window_id)

    def static(self, path, window_id=None):
        return 200, b"viewer", "text/html"

    async def bridge(self, window_id, token, ws):
        try:
            await ws.send_bytes(b"viewer")
            while True:
                await ws.receive()
        finally:
            self.released.set()


@pytest.fixture
def hosted():
    backend = Backend()
    enabled = [True]

    async def authorize(request, link, operation):
        # Synthetic trusted host seam; real hosts use their verified session.
        return enabled[0] and request.headers.get("x-test-actor") == link.context.owner

    relay = Relay(backend, "https://example.com/connect", authorize=authorize)
    link = relay.create(
        "private-account", label="Private account label", context=AttemptContext("owner-a", "agent-a", "target-a")
    )
    with TestClient(relay.app(), base_url="https://example.com") as client:
        yield backend, enabled, relay, link, client


def test_authenticated_links_require_private_host_assigned_context(hosted):
    backend, _, relay, link, _ = hosted
    with pytest.raises(ValueError, match="owner"):
        relay.create("account")
    assert link.public() == {"state": "ready", "host": ""}
    relay.start(link, "desktop")
    assert backend.started == [{}]
    assert "owner-a" not in repr(link)


@pytest.mark.parametrize(
    "path,method", [("", "GET"), ("/state", "GET"), ("/start", "POST"), ("/cancel", "POST"), ("/novnc/vnc.html", "GET")]
)
def test_another_actor_cannot_read_or_change_an_attempt(hosted, path, method):
    backend, _, _, link, client = hosted
    response = client.request(
        method, "/" + link.id + path, headers={"x-test-actor": "owner-b", "origin": "https://example.com"}
    )
    assert response.status_code == 404
    assert "Private account" not in response.text and "target-a" not in response.text
    assert backend.started == [] and backend.closed == []


@pytest.mark.parametrize("origin", [None, "https://other.example.com"])
def test_cookie_authenticated_mutations_refuse_missing_or_foreign_origin(hosted, origin):
    backend, _, _, link, client = hosted
    headers = {"x-test-actor": "owner-a", **({"origin": origin} if origin else {})}
    assert client.post("/" + link.id + "/start", headers=headers).status_code == 404
    assert not backend.started


def test_preview_does_not_launch_and_authorized_start_keeps_context_private(hosted):
    backend, _, _, link, client = hosted
    headers = {"x-test-actor": "owner-a", "origin": "https://example.com"}
    assert client.get("/" + link.id, headers=headers).status_code == 200
    assert not backend.started
    response = client.post("/" + link.id + "/start", headers=headers)
    assert response.status_code == 200 and len(backend.started) == 1
    assert not any(value in response.text for value in ["private-view-token", "owner-a", "agent-a", "target-a"])


def test_existing_view_is_closed_and_reaped_after_permission_is_removed(hosted):
    backend, enabled, relay, link, client = hosted
    relay.start(link, "desktop")
    link.state = "waiting"
    headers = {"x-test-actor": "owner-a", "origin": "https://example.com"}
    with client.websocket_connect("/" + link.id + "/vnc", headers=headers) as ws:
        assert ws.receive_bytes() == b"viewer"
        enabled[0] = False
        with pytest.raises(WebSocketDisconnect):
            ws.receive_bytes()
    assert backend.released.wait(2)


def test_viewer_rejects_another_actor_even_with_the_link(hosted):
    _, _, relay, link, client = hosted
    relay.start(link, "desktop")
    link.state = "waiting"
    with (
        pytest.raises(WebSocketDisconnect),
        client.websocket_connect(
            "/" + link.id + "/vnc", headers={"x-test-actor": "owner-b", "origin": "https://example.com"}
        ),
    ):
        pass


def test_policy_failure_never_downgrades_to_capability_access(hosted, caplog):
    _, _, relay, link, client = hosted

    def broken(*args):
        raise ValueError("private-policy-value")

    relay._authorize = broken
    assert client.get("/" + link.id).status_code == 404
    assert "private-policy-value" not in caplog.text


@pytest.mark.parametrize("url", ["https://other.example.com", "//other.example.com", "/\\other", "/\nother"])
def test_return_navigation_is_local(url):
    with pytest.raises(ValueError):
        PageText(return_url=url)
