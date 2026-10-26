"""Embedded kept sessions: no HTTP result transfer or page-driven completion."""

import asyncio
import contextlib
import threading
import time

import pytest
from starlette.applications import Starlette
from starlette.testclient import TestClient

from signin_window.client import LocalBackend
from signin_window.page import PageText
from signin_window.relay import Relay
from signin_window.service import Windows


def until(predicate):
    deadline = time.monotonic() + 3
    while not predicate():
        assert time.monotonic() < deadline
        time.sleep(0.01)


def test_completion_without_page_polls_and_reload_does_not_start_again(tmp_path):
    release = threading.Event()
    saved = []
    starts = []

    async def runner(window):
        starts.append(window.id)
        window.waiting("accounts.example.com")
        while not release.is_set():
            await asyncio.sleep(0.01)
        window.saving()
        await asyncio.sleep(0.05)
        saved.append(window.id)
        window.finish("connected")

    windows = Windows(runner)
    windows.start_display = lambda window: None
    windows.stop_display = lambda window: None

    @contextlib.asynccontextmanager
    async def lifespan(app):
        backend = LocalBackend(windows, tmp_path)
        relay = Relay(backend, "https://example.com/connect", text=PageText(reconnect=True))
        app.router.routes.extend(relay.routes("/connect"))
        app.state.link = relay.create("example-account")
        async with windows.lifespan(), relay.lifespan():
            yield

    app = Starlette(lifespan=lifespan)
    with TestClient(app) as client:
        link = app.state.link
        path = "/connect/" + link.id
        client.post(path + "/start", json={"layout": "desktop"})
        until(lambda: link.state == "waiting")
        # Reload and duplicate starts attach to the current attempt.
        assert client.get(path).status_code == 200
        client.post(path + "/start", json={})
        assert len(starts) == 1
        release.set()
        until(lambda: link.state == "connected")  # no /state request drives the save
        assert saved == starts
        assert "cookies" not in client.get(path + "/state").text


def test_deadline_without_any_api_requests():
    async def exercise():
        stopped = []

        async def runner(window):
            window.waiting()
            await asyncio.Event().wait()

        windows = Windows(runner, minutes=0.001)
        windows.start_display = lambda window: None
        windows.stop_display = lambda window: stopped.append(window.id)
        async with windows.lifespan():
            window = await windows.start()
            await asyncio.sleep(0.25)
            assert window.state == "expired"
            assert stopped == [window.id]

    asyncio.run(exercise())


def test_saving_closes_view_and_survives_cancel_but_is_bounded():
    async def exercise():
        saved = []

        async def runner(window):
            window.waiting()
            window.saving()
            await asyncio.sleep(0.1)
            saved.append(window.id)
            window.finish("connected")

        windows = Windows(runner, save_seconds=1)
        windows.start_display = lambda window: None
        windows.stop_display = lambda window: None
        async with windows.lifespan():
            window = await windows.start()
            await asyncio.sleep(0.02)
            await windows.close(window.id)
            assert window.state == "saving"
        assert window.state == "connected" and saved == [window.id]

        async def stalled(window):
            window.saving()
            await asyncio.Event().wait()

        windows = Windows(stalled, save_seconds=0.05)
        windows.start_display = lambda window: None
        windows.stop_display = lambda window: None
        async with windows.lifespan():
            window = await windows.start()
            await asyncio.sleep(0.25)
            assert window.state == "cancelled"

    asyncio.run(exercise())


def test_existing_display_is_borrowed_and_only_vnc_is_owned(monkeypatch):
    commands = []

    class Process:
        def __init__(self, argv, **kwargs):
            commands.append(argv)

        def poll(self):
            return None

        def terminate(self):
            commands.append("terminated")

        def wait(self, **kwargs):
            return 0

    monkeypatch.setattr("signin_window.service.subprocess.Popen", Process)
    windows = Windows(lambda window: None, display=":88")
    windows._wait = lambda *args: None
    windows._free_port = lambda taken: 5999

    async def exercise():
        window = await windows.start()
        assert window.display == ":88"
        await window.task

    asyncio.run(exercise())
    assert commands[0][0] == "x11vnc"
    assert commands[0][commands[0].index("-display") + 1] == ":88"
    assert commands[1:] == ["terminated"]
    with pytest.raises(ValueError):
        Windows(lambda window: None, display=":88", slots=2)


def test_repeated_deadline_checks_do_not_release_a_running_sync_runner():
    async def exercise():
        release = threading.Event()
        exited = threading.Event()
        cleaned = []

        def runner(window):
            window.waiting()
            window.cancelled.wait(3)
            release.wait(3)  # cooperative shutdown that lasts more than one watchdog tick
            exited.set()

        windows = Windows(runner, minutes=0.001)
        windows.start_display = lambda window: None
        windows.stop_display = lambda window: cleaned.append(exited.is_set())
        async with windows.lifespan():
            window = await windows.start()
            try:
                await asyncio.sleep(0.35)
                assert window.cancelled.is_set()
                assert window.ended_at is None and cleaned == []
            finally:
                release.set()
                await window.task
            assert cleaned == [True]

    asyncio.run(exercise())
