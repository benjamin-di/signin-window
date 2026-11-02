"""Fresh-authentication step-up in a real browser, under the Connections page policy.

The other OIDC tests drive the protocol with an HTTP client, which ignores the
Content Security Policy. Here headless Chromium submits a form on a real
Connections page served by ``BrowserAuth``, so ``form-action 'self'`` applies to
every redirect after the submission. A synthetic identity provider on a second
loopback origin answers ``/authorize``; its signed tokens come from
``oidc_provider.Provider`` as in the protocol tests. Skipped without Playwright
or its Chromium: ``uv sync --group browser``, then ``uv run playwright install
chromium``.
"""

from __future__ import annotations

import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from oidc_provider import Provider
from starlette.applications import Starlette
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse
from starlette.routing import Route

from signin_window.connections import page
from signin_window.oidc import BrowserAuth, OIDCConfig

sync_api = pytest.importorskip("playwright.sync_api")
uvicorn = pytest.importorskip("uvicorn")


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.fixture
def connections(tmp_path):
    issuer_port, app_port = free_port(), free_port()
    provider = Provider(issuer=f"http://127.0.0.1:{issuer_port}")
    provider.tamper = {"auth_time": int(time.time()) - 3600}  # An older provider session: not fresh.
    authorizations = []

    class Authorize(BaseHTTPRequestHandler):
        def do_GET(self):
            authorizations.append(self.path)
            self.send_response(302)
            self.send_header("Location", provider.authorize(provider.issuer + self.path))
            self.end_headers()

        def log_message(self, *_):
            pass

    identity_server = ThreadingHTTPServer(("127.0.0.1", issuer_port), Authorize)
    threading.Thread(target=identity_server.serve_forever, daemon=True).start()

    config = OIDCConfig(
        provider.issuer,
        "example-app",
        f"http://localhost:{app_port}",
        tmp_path / "browser",
        required_group="example-users",
        allow_loopback_http=True,
    )
    auth = BrowserAuth(config, transport=provider.transport())

    async def home(request):
        if auth.identity(request) is None:
            return RedirectResponse("/connections/login", status_code=303)
        forms = (
            '<form method="post" action="/connections/act"><button id="act">Connect</button></form>'
            '<form method="post" action="/connections/old"><button id="old">Connect (redirect)</button></form>'
        )
        return HTMLResponse(page("Example", forms))

    async def act(request):
        if auth.identity(request) is None or not auth.origin_ok(request):
            return auth.refused(request)
        return auth.require_fresh(request, action="connect an account") or JSONResponse({"done": True})

    async def old(_request):
        # The pattern this library replaces: redirect a submitted form into step-up.
        return RedirectResponse(auth.step_up_url(), status_code=303)

    app = auth.middleware(
        Starlette(
            routes=[
                *auth.routes(),
                Route("/connections/", home),
                Route("/connections/act", act, methods=["POST"]),
                Route("/connections/old", old, methods=["POST"]),
            ]
        )
    )
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=app_port, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.time() + 10
    while not server.started:
        assert time.time() < deadline, "application server did not start"
        time.sleep(0.05)
    try:
        yield config.public_url, provider, authorizations
    finally:
        server.should_exit = True
        thread.join(5)
        identity_server.shutdown()


@pytest.fixture
def browser_page():
    with sync_api.sync_playwright() as driver:
        try:
            browser = driver.chromium.launch(headless=True)
        except Exception as exc:
            pytest.skip(f"chromium unavailable: {exc}")
        try:
            yield browser.new_page()
        finally:
            browser.close()


def test_a_fresh_auth_action_reaches_the_provider_and_returns_fresh(connections, browser_page):
    origin, provider, authorizations = connections
    browser_page.goto(origin + "/connections/")
    assert len(authorizations) == 1 and "prompt=login" not in authorizations[0]

    browser_page.click("#act")
    browser_page.get_by_role("heading", name="Confirm it's you").wait_for()
    assert browser_page.url == origin + "/connections/act"

    provider.tamper = {}  # The provider confirms the person now.
    browser_page.get_by_role("link", name="Confirm and continue").click()
    browser_page.wait_for_url(origin + "/connections/")
    assert len(authorizations) == 2 and "prompt=login" in authorizations[1]

    with browser_page.expect_navigation():
        browser_page.click("#act")
    assert '"done":true' in browser_page.content()


def test_a_submitted_form_redirected_into_step_up_is_cancelled_by_the_page_policy(connections, browser_page):
    origin, _, authorizations = connections
    browser_page.goto(origin + "/connections/")
    blocked = []
    browser_page.on("console", lambda message: blocked.append(message.text) if "form-action" in message.text else None)
    browser_page.click("#old")
    browser_page.wait_for_timeout(1000)
    # The provider never sees the step-up and the person is still signed in on the same page.
    assert len(authorizations) == 1 and blocked
    browser_page.goto(origin + "/connections/")
    browser_page.locator("#act").wait_for()
    assert len(authorizations) == 1
