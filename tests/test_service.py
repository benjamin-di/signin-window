"""The login service's windows and API, with fake runners and no display: slots, the one-time hand-over, kept
sessions, one window per key, time limits, the shared lock, and the bearer and view token on every route."""

from __future__ import annotations

import asyncio
import socket
import sys
import threading
import time

import pytest
from starlette.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from signin_window import service
from signin_window.service import Windows, build_app

TOKEN = "t" * 40
AUTH = {"Authorization": f"Bearer {TOKEN}"}


class Clock:
    now = 1000.0

    def __call__(self) -> float:
        return self.now


def no_display(windows: Windows) -> Windows:
    windows.start_display = lambda window: None  # no Xvfb in tests
    windows.stop_display = lambda window: window.procs.clear()
    return windows


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def waiting_until(release: dict, outcome=None):
    """A runner that shows the sign-in page, then waits until a test releases it."""

    async def runner(window):
        window.waiting("accounts.example.com")
        while not release.get(window.id):
            await asyncio.sleep(0.01)
        if outcome is not None:
            return outcome(window)
        return {"cookies": [{"name": "sid", "value": "secret"}]}

    return runner


def poll(client: TestClient, window_id: str, until: str) -> dict:
    for _ in range(300):
        body = client.get(f"/logins/{window_id}", headers=AUTH).json()
        if body.get("state") == until:
            return body
        time.sleep(0.01)
    raise AssertionError(f"never {until}: {body}")


def app_for(windows: Windows, tmp_path, **kwargs):
    return build_app(windows, token=TOKEN, novnc_dir=tmp_path, **kwargs)


def test_every_route_but_health_novnc_and_the_view_needs_the_bearer(tmp_path):
    (tmp_path / "vnc.html").write_text("<html></html>")
    app = app_for(no_display(Windows(waiting_until({}))), tmp_path)
    with TestClient(app) as client:
        assert client.get("/health").status_code == 200
        assert client.get("/novnc/vnc.html").status_code == 200
        assert client.post("/logins", json={}).status_code == 401
        assert client.post("/logins", json={}, headers={"Authorization": "Bearer wrong"}).status_code == 401
        assert client.get("/logins/abc", headers=AUTH).status_code == 404
        assert client.get("/view/abc").status_code == 404  # the view needs its token
        with pytest.raises(WebSocketDisconnect), client.websocket_connect("/logins/abc/vnc"):
            pass


def test_a_short_bearer_is_refused(tmp_path):
    with pytest.raises(ValueError):
        build_app(Windows(waiting_until({})), token="short", novnc_dir=tmp_path)


def test_a_handed_over_session_is_taken_once_and_frees_the_slot(tmp_path):
    release: dict = {}
    app = app_for(no_display(Windows(waiting_until(release))), tmp_path)
    with TestClient(app) as client:
        started = client.post("/logins", json={"layout": "phone"}, headers=AUTH)
        assert started.status_code == 201 and started.json()["layout"] == "phone" and started.json()["view_token"]
        window_id = started.json()["id"]
        assert poll(client, window_id, "waiting")["host"] == "accounts.example.com"
        assert client.post("/logins", json={}, headers=AUTH).status_code == 503  # the only slot is taken
        assert client.post(f"/logins/{window_id}/result", headers=AUTH).status_code == 409  # not signed in yet
        release[window_id] = True
        assert "secret" not in str(poll(client, window_id, "signed_in"))  # the state never carries the session
        taken = client.post(f"/logins/{window_id}/result", headers=AUTH)
        assert taken.status_code == 200 and taken.json()["cookies"][0]["value"] == "secret"
        assert client.post(f"/logins/{window_id}/result", headers=AUTH).status_code == 409  # once only
        assert client.get(f"/logins/{window_id}", headers=AUTH).json()["state"] == "closed"
        assert client.post("/logins", json={}, headers=AUTH).status_code == 201  # the slot is free again


def test_a_kept_session_ends_in_the_runners_own_state_with_its_report(tmp_path):
    release: dict = {}

    def connected(window):
        window.report(account="jane@example.com")
        window.finish("connected")

    app = app_for(no_display(Windows(waiting_until(release, connected))), tmp_path)
    with TestClient(app) as client:
        window_id = client.post("/logins", json={}, headers=AUTH).json()["id"]
        release[window_id] = True
        body = poll(client, window_id, "connected")
        assert body["account"] == "jane@example.com"
        assert client.post(f"/logins/{window_id}/result", headers=AUTH).status_code == 409  # nothing to hand over


def test_a_runner_cannot_report_over_the_windows_own_fields_or_finish_in_an_open_state():
    window = service.Window("w" * 24, "desktop", 0, 0.0, 10.0)
    window.report(state="connected", id="x", account="a")
    assert window.public()["state"] == "starting" and window.public()["id"] == "w" * 24
    assert window.public()["account"] == "a"
    for state in ("waiting", "signed_in", "Bad State"):
        with pytest.raises(ValueError):
            window.finish(state)


def test_a_failing_runner_ends_failed_with_its_error_type(tmp_path):
    async def runner(window):
        window.waiting()
        raise RuntimeError("the page broke")

    app = app_for(no_display(Windows(runner)), tmp_path)
    with TestClient(app) as client:
        window_id = client.post("/logins", json={}, headers=AUTH).json()["id"]
        assert poll(client, window_id, "failed")["error"] == "RuntimeError"


def test_a_runner_that_returns_nothing_failed(tmp_path):
    async def runner(window):
        window.waiting()

    app = app_for(no_display(Windows(runner)), tmp_path)
    with TestClient(app) as client:
        window_id = client.post("/logins", json={}, headers=AUTH).json()["id"]
        assert poll(client, window_id, "failed")["error"] == "no_session"


def test_start_params_validate_the_request_and_reach_the_runner(tmp_path):
    seen = {}

    async def runner(window):
        seen.update(window.params)
        window.waiting()
        await asyncio.sleep(5)

    def start_params(body):
        if body.get("site") not in ("example.com", "example.org"):
            raise ValueError("site")
        return {"site": body["site"], "key": body["site"]}

    app = app_for(no_display(Windows(runner, slots=2)), tmp_path, start_params=start_params)
    with TestClient(app) as client:
        assert client.post("/logins", json={"site": "evil.example"}, headers=AUTH).status_code == 400
        window_id = client.post("/logins", json={"site": "example.org"}, headers=AUTH).json()["id"]
        poll(client, window_id, "waiting")
        assert seen == {"site": "example.org", "key": "example.org"}


def test_a_newer_window_for_the_same_key_cancels_the_older(tmp_path):
    def start_params(body):
        return {"key": body.get("account")}

    app = app_for(no_display(Windows(waiting_until({}), slots=2)), tmp_path, start_params=start_params)
    with TestClient(app) as client:
        first = client.post("/logins", json={"account": "a"}, headers=AUTH).json()["id"]
        other = client.post("/logins", json={"account": "b"}, headers=AUTH).json()["id"]
        poll(client, first, "waiting")
        client.post("/logins", json={"account": "a"}, headers=AUTH)
        poll(client, first, "cancelled")
        assert client.get(f"/logins/{other}", headers=AUTH).json()["state"] == "waiting"


def test_cancel_closes_an_open_window(tmp_path):
    app = app_for(no_display(Windows(waiting_until({}))), tmp_path)
    with TestClient(app) as client:
        window_id = client.post("/logins", json={}, headers=AUTH).json()["id"]
        poll(client, window_id, "waiting")
        assert client.delete(f"/logins/{window_id}", headers=AUTH).status_code == 204
        poll(client, window_id, "cancelled")


def test_windows_past_their_time_expire_and_ended_ones_are_forgotten(tmp_path):
    clock, release = Clock(), {}
    windows = no_display(Windows(waiting_until(release), minutes=15, clock=clock))
    app = app_for(windows, tmp_path)
    with TestClient(app) as client:
        window_id = client.post("/logins", json={}, headers=AUTH).json()["id"]
        poll(client, window_id, "waiting")
        clock.now += 16 * 60
        poll(client, window_id, "expired")
        clock.now += service.ENDED_TTL + 1
        assert client.get(f"/logins/{window_id}", headers=AUTH).status_code == 404
        assert client.post("/logins", json={}, headers=AUTH).status_code == 201


def test_a_session_nobody_takes_is_dropped(tmp_path):
    clock, release = Clock(), {}
    app = app_for(no_display(Windows(waiting_until(release), clock=clock)), tmp_path)
    with TestClient(app) as client:
        window_id = client.post("/logins", json={}, headers=AUTH).json()["id"]
        release[window_id] = True
        poll(client, window_id, "signed_in")
        clock.now += service.RESULT_TTL + 1
        assert client.get(f"/logins/{window_id}", headers=AUTH).json()["state"] == "expired"
        assert client.post(f"/logins/{window_id}/result", headers=AUTH).status_code == 409


def test_a_window_that_cannot_get_the_shared_lock_is_busy(tmp_path):
    lock = threading.Lock()
    lock.acquire()
    app = app_for(no_display(Windows(waiting_until({}), lock=lock, lock_wait=0.05)), tmp_path)
    with TestClient(app) as client:
        window_id = client.post("/logins", json={}, headers=AUTH).json()["id"]
        poll(client, window_id, "busy")
    lock.release()


def test_a_threaded_runner_holds_the_lock_until_it_has_stopped(tmp_path):
    lock, stopped = threading.Lock(), threading.Event()

    def runner(window):  # a plain function: runs in a thread, polls window.cancelled
        window.waiting()
        while not window.cancelled.wait(0.01):
            pass
        time.sleep(0.2)  # the browser takes a moment to close
        stopped.set()

    app = app_for(no_display(Windows(runner, lock=lock)), tmp_path)
    with TestClient(app) as client:
        window_id = client.post("/logins", json={}, headers=AUTH).json()["id"]
        poll(client, window_id, "waiting")
        assert lock.locked()
        client.delete(f"/logins/{window_id}", headers=AUTH)
        poll(client, window_id, "cancelled")
        for _ in range(100):
            if not lock.locked():
                break
            time.sleep(0.01)
        assert stopped.is_set() and not lock.locked()


def test_the_view_and_its_stream_need_the_windows_view_token(tmp_path):
    app = app_for(no_display(Windows(waiting_until({}))), tmp_path, title="Sign in to <Example>")
    with TestClient(app) as client:
        started = client.post("/logins", json={}, headers=AUTH).json()
        window_id, token = started["id"], started["view_token"]
        poll(client, window_id, "waiting")
        assert client.get(f"/view/{window_id}?t=wrong").status_code == 404
        page = client.get(f"/view/{window_id}?t={token}")
        assert page.status_code == 200 and "Sign in to &lt;Example&gt;" in page.text
        assert page.headers["cache-control"] == "no-store"
        assert client.get(f"/view/{window_id}/state?t={token}").json()["state"] == "waiting"
        with pytest.raises(WebSocketDisconnect), client.websocket_connect(f"/logins/{window_id}/vnc?t=wrong"):
            pass


def test_the_stream_is_only_open_while_the_sign_in_page_is_shown(tmp_path):
    async def runner(window):
        await asyncio.sleep(5)  # never reaches the sign-in page

    app = app_for(no_display(Windows(runner)), tmp_path)
    with TestClient(app) as client:
        started = client.post("/logins", json={}, headers=AUTH).json()
        with (
            pytest.raises(WebSocketDisconnect),
            client.websocket_connect(f"/logins/{started['id']}/vnc?t={started['view_token']}"),
        ):
            pass


def test_the_stream_relays_the_windows_vnc_bytes(tmp_path):
    received: list[bytes] = []

    async def vnc_server(reader, writer):
        writer.write(b"RFB 003.008\n")
        await writer.drain()
        received.append(await reader.read(100))
        writer.close()

    loop = asyncio.new_event_loop()
    server = loop.run_until_complete(asyncio.start_server(vnc_server, "127.0.0.1", 0))
    port = server.sockets[0].getsockname()[1]
    thread = threading.Thread(target=loop.run_forever, daemon=True)
    thread.start()
    try:
        app = app_for(no_display(Windows(waiting_until({}), vnc_base=port)), tmp_path)
        with TestClient(app) as client:
            started = client.post("/logins", json={}, headers=AUTH).json()
            poll(client, started["id"], "waiting")
            with client.websocket_connect(f"/logins/{started['id']}/vnc?t={started['view_token']}") as ws:
                assert ws.receive_bytes() == b"RFB 003.008\n"
                ws.send_bytes(b"RFB 003.008\n")
        for _ in range(100):
            if received:
                break
            time.sleep(0.01)
        assert received == [b"RFB 003.008\n"]
    finally:
        loop.call_soon_threadsafe(loop.stop)
        thread.join(2)


def test_slots_are_bounded():
    with pytest.raises(ValueError):
        Windows(waiting_until({}), slots=0)
    with pytest.raises(ValueError):
        Windows(waiting_until({}), slots=10)


def fake_x(tmp_path):
    """Stand-ins for Xvfb (makes its socket, then waits) and x11vnc (listens on -rfbport, then waits)."""
    xvfb, x11vnc = tmp_path / "Xvfb", tmp_path / "x11vnc"
    xvfb.write_text(
        f"#!/bin/sh\nmkdir -p {tmp_path}/.X11-unix\nn=${{1#:}}\ntouch {tmp_path}/.X11-unix/X$n\nexec sleep 30\n"
    )
    x11vnc.write_text(
        f"#!{sys.executable}\nimport socket, sys, time\n"
        "port = int(sys.argv[sys.argv.index('-rfbport') + 1])\n"
        "s = socket.socket(); s.bind(('127.0.0.1', port)); s.listen(); time.sleep(30)\n"
    )
    for script in (xvfb, x11vnc):
        script.chmod(0o755)
    return str(xvfb), str(x11vnc)


def test_the_display_and_its_vnc_server_start_and_stop(tmp_path, monkeypatch):
    xvfb, x11vnc = fake_x(tmp_path)
    monkeypatch.setattr(Windows, "x_tmp", tmp_path)
    windows = Windows(waiting_until({}), xvfb=xvfb, x11vnc=x11vnc, vnc_base=free_port())
    window = service.Window("w" * 24, "desktop", 0, 0.0, 10.0)
    windows.start_display(window)
    procs = list(window.procs)
    assert len(procs) == 2 and all(proc.poll() is None for proc in procs)
    assert window.display == ":90" and (tmp_path / ".X11-unix" / "X90").exists()
    windows.stop_display(window)
    assert window.procs == [] and all(proc.poll() is not None for proc in procs)


def test_a_display_or_port_still_held_is_skipped(tmp_path, monkeypatch):
    xvfb, x11vnc = fake_x(tmp_path)
    monkeypatch.setattr(Windows, "x_tmp", tmp_path)
    (tmp_path / ".X90-lock").write_text("12345")  # a display not released yet
    port = free_port()
    held = socket.socket()
    held.bind(("127.0.0.1", port))  # the last window's VNC port, not released yet
    try:
        windows = Windows(waiting_until({}), xvfb=xvfb, x11vnc=x11vnc, vnc_base=port)
        window = service.Window("w" * 24, "desktop", 0, 0.0, 10.0)
        windows.start_display(window)
        assert window.display == ":91" and window.vnc_port != port
        windows.stop_display(window)
    finally:
        held.close()


def test_a_display_that_exits_at_once_is_an_error(tmp_path):
    windows = Windows(waiting_until({}), xvfb="/bin/false", x11vnc="/bin/false")
    window = service.Window("w" * 24, "desktop", 0, 0.0, 10.0)
    with pytest.raises(RuntimeError):
        windows.start_display(window)
    windows.stop_display(window)
