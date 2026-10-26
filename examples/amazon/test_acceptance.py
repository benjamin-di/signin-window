"""Real Chromium/noVNC acceptance against a local provider; no Amazon traffic."""

import json
import logging
import os
import socket
import threading
import time

import httpx
import pytest
import uvicorn
from amazonorders.conf import AmazonOrdersConfig
from app import make_app
from playwright.sync_api import sync_playwright
from synthetic import Provider

from signin_window.service import Windows

TOKEN = "synthetic-prototype-token-0000000000000000"


def wait_for(predicate, seconds=15):
    deadline = time.monotonic() + seconds
    while not predicate():
        assert time.monotonic() < deadline, "acceptance deadline exceeded"
        time.sleep(0.05)


@pytest.fixture
def host(tmp_path):
    with Provider() as provider:
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        origin = f"http://127.0.0.1:{sock.getsockname()[1]}"
        jar = tmp_path / "cookies.json"
        config = AmazonOrdersConfig(data={"cookie_jar_path": str(jar), "request_timeout": 2})
        provider.configure(config)

        def windows_factory(runner, **kwargs):
            def observed(window):
                try:
                    return runner(window)
                except Exception:
                    logging.getLogger("synthetic_acceptance").exception("Synthetic runner failed")
                    raise

            return Windows(observed, xvfb=os.environ["SIGNIN_XVFB"], x11vnc=os.environ["SIGNIN_X11VNC"], **kwargs)

        app = make_app(
            config,
            public_url=origin,
            token=TOKEN,
            novnc_dir=os.environ["NOVNC_DIR"],
            synthetic=True,
            windows_factory=windows_factory,
        )
        server = uvicorn.Server(uvicorn.Config(app, log_level="error", access_log=False))
        thread = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
        thread.start()
        wait_for(lambda: server.started)
        try:
            yield app, provider, origin, jar
        finally:
            server.should_exit = True
            thread.join(10)
            sock.close()
            assert not thread.is_alive(), "application did not stop"


def rpc(origin, method, params):
    response = httpx.post(
        origin + "/mcp",
        headers={"Authorization": f"Bearer {TOKEN}", "Accept": "application/json, text/event-stream"},
        json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
        timeout=20,
    )
    assert response.status_code == 200, response.text
    packet = response.json()
    assert "error" not in packet, packet
    return packet["result"]


def new_link(origin):
    result = rpc(origin, "tools/call", {"name": "amazon_connect", "arguments": {}})
    assert not result.get("isError"), result
    return json.loads(result["content"][0]["text"])["url"]


def interact(page, url, *, reload=False):
    page.goto(url)
    page.locator("#go").click()
    frame = page.frame_locator("iframe")
    frame.locator("canvas").wait_for(timeout=15000)
    page.wait_for_function("document.querySelector('#status').textContent.includes('Sign in')")
    if reload:
        page.reload()
        frame = page.frame_locator("iframe")
        frame.locator("canvas").wait_for(timeout=15000)
    frame.locator("html.noVNC_connected").wait_for(timeout=15000)
    # Test-only human input goes through the actual noVNC viewer, not the provider DOM.
    frame.locator("canvas").click(position={"x": 200, "y": 200})
    page.keyboard.press("Tab")
    page.keyboard.press("Enter")


def test_real_viewer_reload_sign_in_and_existing_mcp_tools(host):
    app, provider, origin, jar = host
    assert httpx.post(origin + "/mcp").status_code == 401
    tools = rpc(origin, "tools/list", {})["tools"]
    assert {"amazon_connect", "sign_in", "check_session", "get_orders"} <= {t["name"] for t in tools}
    url = new_link(origin)
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        page = browser.new_page()
        interact(page, url, reload=True)
        wait_for(lambda: jar.exists())
        wait_for(lambda: next(iter(app.state.connect.relay._links.values())).state == "connected")
        assert provider.requests.count("/signin") == 1
        page.locator("#done").wait_for(state="visible", timeout=15000)
        assert "Connected" in page.locator("#done").inner_text()
        browser.close()
    result = rpc(origin, "tools/call", {"name": "check_session", "arguments": {}})
    assert not result.get("isError"), result
    assert '"signed_in": true' in result["content"][0]["text"]
    assert "synthetic-accepted" in jar.read_text()
    windows = list(app.state.windows._windows.values())
    assert len(windows) == 1 and not windows[0].procs and not windows[0].profiles


def test_verification_failure_preserves_existing_session(host):
    app, provider, origin, jar = host
    original = b'[{"name":"sid","value":"synthetic-previous","domain":"127.0.0.1"}]'
    jar.write_bytes(original)
    provider.reject = True
    url = new_link(origin)
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        interact(browser.new_page(), url)
        link = next(iter(app.state.connect.relay._links.values()))
        wait_for(lambda: link.state == "failed")
        browser.close()
    assert jar.read_bytes() == original


def test_saving_finishes_after_the_person_closes_the_page(host):
    app, provider, origin, jar = host
    url = new_link(origin)
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        page = browser.new_page()
        interact(page, url)
        wait_for(lambda: any(w.state == "saving" for w in app.state.windows._windows.values()))
        page.close()
        wait_for(lambda: jar.exists())
        wait_for(lambda: next(iter(app.state.connect.relay._links.values())).state == "connected")
        browser.close()
    assert provider.requests.count("/signin") == 1


def test_explicit_cancel_closes_the_browser_without_saving(host):
    app, _provider, origin, jar = host
    url = new_link(origin)
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        page = browser.new_page()
        page.goto(url)
        page.locator("#go").click()
        page.frame_locator("iframe").locator("html.noVNC_connected").wait_for(timeout=15000)
        page.get_by_role("button", name="Cancel", exact=True).click()
        wait_for(lambda: all(w.state == "cancelled" for w in app.state.windows._windows.values()))
        browser.close()
    assert not jar.exists()
    wait_for(lambda: all(not w.procs for w in app.state.windows._windows.values()))


def test_an_older_attempt_cannot_publish_after_a_replacement_link(host):
    app, _provider, origin, jar = host
    original = b'[{"name":"sid","value":"synthetic-previous","domain":"127.0.0.1"}]'
    jar.write_bytes(original)
    url = new_link(origin)
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        page = browser.new_page()
        interact(page, url)
        wait_for(lambda: any(w.state == "saving" for w in app.state.windows._windows.values()))
        assert new_link(origin) != url
        wait_for(lambda: all(w.state == "failed" for w in app.state.windows._windows.values()))
        browser.close()
    assert jar.read_bytes() == original
