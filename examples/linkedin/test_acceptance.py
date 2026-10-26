"""Real borrowed-display viewer and upstream profile lifecycle, with synthetic pages."""

import asyncio
import os
import socket
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import httpx
import pytest
import uvicorn
from app import make_app
from linkedin_mcp_server.config import AppConfig
from linkedin_mcp_server.profile_lease import get_profile_lease
from linkedin_mcp_server.session_state import load_source_state, portable_cookie_path
from playwright.sync_api import sync_playwright

from signin_window.service import Windows

TOKEN = "synthetic-linkedin-viewer-token-0000000000"


def wait_for(predicate, seconds=20):
    deadline = time.monotonic() + seconds
    while not predicate():
        assert time.monotonic() < deadline, "acceptance deadline exceeded"
        time.sleep(0.05)


@pytest.fixture
def host(tmp_path, monkeypatch, request):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "viewer-config"))
    display = next(
        n
        for n in range(210, 310)
        if not Path(f"/tmp/.X{n}-lock").exists() and not Path(f"/tmp/.X11-unix/X{n}").exists()
    )
    process = subprocess.Popen(
        [os.environ["SIGNIN_XVFB"], f":{display}", "-screen", "0", "1920x1080x24", "-nolisten", "tcp"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    wait_for(lambda: Path(f"/tmp/.X11-unix/X{display}").exists())
    profile = tmp_path / "auth" / "profile"
    config = AppConfig()
    config.browser.user_data_dir = str(profile)
    config.browser.chrome_path = os.environ["LINKEDIN_TEST_CHROME"]
    config.browser.login_timeout_seconds = 30
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    origin = f"http://127.0.0.1:{sock.getsockname()[1]}"

    def factory(runner, **kwargs):
        return Windows(runner, x11vnc=os.environ["SIGNIN_X11VNC"], **kwargs)

    app = make_app(
        config,
        display=f":{display}",
        public_url=origin,
        token=TOKEN,
        novnc_dir=os.environ["NOVNC_DIR"],
        windows_factory=factory,
        fail_export=getattr(request, "param", False),
    )
    server = uvicorn.Server(uvicorn.Config(app, log_level="error", access_log=False))
    thread = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
    thread.start()
    wait_for(lambda: server.started)
    try:
        yield app, origin, profile, process
    finally:
        server.should_exit = True
        thread.join(55)
        sock.close()
        # The host owns this X server. Both successful and cancelled logins must leave it alive.
        alive = process.poll() is None
        process.terminate()
        process.wait(timeout=5)
        assert alive and not thread.is_alive()


def link(origin):
    response = httpx.post(origin + "/link", headers={"Authorization": "Bearer " + TOKEN})
    assert response.status_code == 200
    return response.json()["url"]


def open_view(page, url, *, reload=False):
    page.goto(url)
    page.locator("#go").click()
    frame = page.frame_locator("iframe")
    frame.locator("html.noVNC_connected").wait_for(timeout=25000)
    if reload:
        page.reload()
        frame = page.frame_locator("iframe")
        frame.locator("html.noVNC_connected").wait_for(timeout=15000)
    return frame


def complete(page, frame):
    frame.locator("canvas").click(position={"x": 300, "y": 300})
    page.keyboard.press("Tab")
    page.keyboard.press("Enter")


def current(app):
    return next(iter(app.state.relay._links.values()))


def test_reload_and_publication_keep_upstream_session_format_and_borrowed_display(host):
    app, origin, profile, display = host
    assert httpx.post(origin + "/link").status_code == 401
    url = link(origin)
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True, executable_path=os.environ["LINKEDIN_TEST_CHROME"])
        page = browser.new_page()
        frame = open_view(page, url, reload=True)
        lease = get_profile_lease(profile)
        with ThreadPoolExecutor(max_workers=1) as pool:
            assert not pool.submit(asyncio.run, lease.acquire(timeout=0.1)).result()
        complete(page, frame)
        wait_for(lambda: current(app).state in ("connected", "failed"))
        assert current(app).state == "connected", [w.error for w in app.state.windows._windows.values()]
        browser.close()
    state = load_source_state(profile)
    assert state is not None and state.login_generation
    assert "synthetic-cookie" in portable_cookie_path(profile).read_text()
    assert display.poll() is None
    assert len(app.state.windows._windows) == 1
    wait_for(lambda: all(not w.procs for w in app.state.windows._windows.values()))
    assert "synthetic-cookie" not in httpx.get(url + "/state").text


def test_page_closure_during_saving_does_not_interrupt_upstream_publication(host):
    app, origin, profile, _display = host
    url = link(origin)
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True, executable_path=os.environ["LINKEDIN_TEST_CHROME"])
        page = browser.new_page()
        complete(page, open_view(page, url))
        wait_for(lambda: any(w.state == "saving" for w in app.state.windows._windows.values()))
        page.close()
        wait_for(lambda: current(app).state in ("connected", "failed"))
        assert current(app).state == "connected"
        browser.close()
    assert load_source_state(profile) is not None


def test_cancel_restores_the_previous_generation_and_releases_the_profile(host):
    app, origin, profile, _display = host
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True, executable_path=os.environ["LINKEDIN_TEST_CHROME"])
        first = browser.new_page()
        complete(first, open_view(first, link(origin)))
        wait_for(lambda: current(app).state in ("connected", "failed"))
        assert current(app).state == "connected"
        generation = load_source_state(profile).login_generation
        previous = portable_cookie_path(profile).read_bytes()
        first.close()
        second = browser.new_page()
        open_view(second, link(origin))
        second.get_by_role("button", name="Cancel", exact=True).click()
        wait_for(lambda: all(not w.procs for w in app.state.windows._windows.values()), seconds=45)
        browser.close()
    assert load_source_state(profile).login_generation == generation
    assert portable_cookie_path(profile).read_bytes() == previous
    # The next independent process may take the restored profile, using upstream's lease.
    lease = get_profile_lease(profile)
    assert asyncio.run(lease.acquire(timeout=1))
    lease.release()


@pytest.mark.parametrize("host", [True], indirect=True)
def test_export_failure_cannot_publish_a_connected_session(host):
    app, origin, profile, _display = host
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True, executable_path=os.environ["LINKEDIN_TEST_CHROME"])
        page = browser.new_page()
        complete(page, open_view(page, link(origin)))
        wait_for(lambda: current(app).state in ("connected", "failed"))
        assert current(app).state == "failed"
        browser.close()
    assert load_source_state(profile) is None
    assert not portable_cookie_path(profile).exists()
    lease = get_profile_lease(profile)
    assert asyncio.run(lease.acquire(timeout=1))
    lease.release()
