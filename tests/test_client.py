"""The MCP server's client against a real login service (uvicorn on loopback): the API with its bearer, the
one-time hand-over, noVNC's files, the live view, and refusals of anything that is not the service's own path."""

from __future__ import annotations

import asyncio
import socket
import threading
import time

import pytest
import uvicorn
from starlette.applications import Starlette
from starlette.routing import WebSocketRoute
from starlette.testclient import TestClient

from signin_window.client import LoginBusy, LoginClient, LoginUnavailable
from signin_window.service import Windows, build_app

TOKEN = "c" * 40


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.fixture
def vnc_port():
    """A stand-in VNC server for window 0: greets, then echoes."""

    async def serve(reader, writer):
        writer.write(b"RFB 003.008\n")
        await writer.drain()
        while data := await reader.read(100):
            writer.write(data)
            await writer.drain()

    loop = asyncio.new_event_loop()
    server = loop.run_until_complete(asyncio.start_server(serve, "127.0.0.1", 0))
    thread = threading.Thread(target=loop.run_forever, daemon=True)
    thread.start()
    yield server.sockets[0].getsockname()[1]
    loop.call_soon_threadsafe(loop.stop)
    thread.join(2)


@pytest.fixture
def service(tmp_path, vnc_port):
    release: dict = {}

    async def runner(window):
        window.waiting("accounts.example.com")
        while not release.get("go"):
            await asyncio.sleep(0.01)
        return {"site": window.params.get("site"), "cookies": [{"name": "sid", "value": "s"}]}

    windows = Windows(runner, slots=1, vnc_base=vnc_port)
    windows.start_display = lambda window: None
    windows.stop_display = lambda window: window.procs.clear()
    (tmp_path / "vnc.html").write_text("<html><head></head></html>")

    def start_params(body):
        return {"site": str(body.get("site", ""))}

    app = build_app(windows, token=TOKEN, novnc_dir=tmp_path, start_params=start_params)
    port = free_port()
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    for _ in range(200):
        if server.started:
            break
        time.sleep(0.02)
    yield f"http://127.0.0.1:{port}", release
    server.should_exit = True
    thread.join(5)


def wait_for(client: LoginClient, window_id: str, state: str) -> dict:
    for _ in range(300):
        body = client.state(window_id)
        if body["state"] == state:
            return body
        time.sleep(0.01)
    raise AssertionError(body)


def test_a_window_from_start_to_hand_over(service):
    url, release = service
    client = LoginClient(url, TOKEN)
    window = client.start("phone", site="example.de")
    assert window["layout"] == "phone" and window["view_token"]
    assert wait_for(client, window["id"], "waiting")["host"] == "accounts.example.com"
    with pytest.raises(LoginBusy):
        client.start()
    assert client.result(window["id"]) is None  # not signed in yet
    release["go"] = True
    wait_for(client, window["id"], "signed_in")
    assert client.result(window["id"]) == {"site": "example.de", "cookies": [{"name": "sid", "value": "s"}]}
    assert client.result(window["id"]) is None  # once only
    assert client.state("x" * 20) == {"state": "unknown"}


def test_close_cancels_a_window(service):
    url, _ = service
    client = LoginClient(url, TOKEN)
    window = client.start()
    wait_for(client, window["id"], "waiting")
    client.close(window["id"])
    wait_for(client, window["id"], "cancelled")


def test_the_token_can_come_from_a_file_read_on_every_call(service, tmp_path):
    url, _ = service
    token_file = tmp_path / "token"
    token_file.write_text(TOKEN + "\n")
    client = LoginClient(url, token_file=token_file)
    assert client.state("x" * 20) == {"state": "unknown"}
    token_file.write_text("w" * 40)
    with pytest.raises(LoginUnavailable):
        client.state("x" * 20)  # 401
    token_file.unlink()
    with pytest.raises(LoginUnavailable):
        client.state("x" * 20)


def test_a_wrong_bearer_or_no_service_is_unavailable(service):
    url, _ = service
    with pytest.raises(LoginUnavailable):
        LoginClient(url, "w" * 40).start()
    with pytest.raises(LoginUnavailable):
        LoginClient(f"http://127.0.0.1:{free_port()}", TOKEN).start()


def test_only_valid_ids_and_novnc_paths_are_asked_for(service):
    url, _ = service
    client = LoginClient(url, TOKEN)
    for bad in ("../health", "a/b", "short", ""):
        with pytest.raises(LoginUnavailable):
            client.state(bad)
    for bad in ("../logins", ".hidden", "a/../b", "/etc/passwd", "a" * 100):
        assert client.static(bad)[0] == 404
    status, body, content_type = client.static("vnc.html")
    assert status == 200 and b"<head>" in body and content_type.startswith("text/html")


def test_the_client_needs_one_token_and_an_http_url():
    with pytest.raises(ValueError):
        LoginClient("http://login:8080")
    with pytest.raises(ValueError):
        LoginClient("http://login:8080", "t", token_file="/x")
    with pytest.raises(ValueError):
        LoginClient("file:///etc", "t")


def test_the_bridge_relays_a_persons_viewer_to_the_window(service):
    url, _ = service
    client = LoginClient(url, TOKEN)
    window = client.start()
    wait_for(client, window["id"], "waiting")

    async def viewer(ws):
        await ws.accept()
        await client.bridge(window["id"], window["view_token"], ws)

    person = TestClient(Starlette(routes=[WebSocketRoute("/vnc", viewer)]))
    with person.websocket_connect("/vnc") as ws:
        assert ws.receive_bytes() == b"RFB 003.008\n"
        ws.send_bytes(b"hello")
        assert ws.receive_bytes() == b"hello"
