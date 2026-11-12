"""Host build footers persist while the application-owned sign-in shells update."""

import json
from types import SimpleNamespace
from urllib.parse import urlsplit

import pytest
from starlette.testclient import TestClient

from signin_window.connections import PageIdentity
from signin_window.connections import page as connections_page
from signin_window.page import PageText, render
from signin_window.service import Window, Windows, build_app

sync_api = pytest.importorskip("playwright.sync_api")
IDENTITY = PageIdentity("Example", "1.2.3", "abcdef1234567890abcdef1234567890abcdef1234")


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


def remember_footer(page):
    footer = page.locator("#page-identity")
    assert footer.is_visible()
    assert footer.get_attribute("data-source-revision") == IDENTITY.source_revision
    assert footer.evaluate("node => getComputedStyle(node).userSelect") == "text"
    assert not footer.locator("code").is_visible()
    footer.locator("summary").click()
    assert footer.locator("code").inner_text() == IDENTITY.source_revision
    assert footer.locator("code").evaluate("node => getComputedStyle(node).userSelect") == "all"
    page.evaluate("window.loadedIdentity = document.getElementById('page-identity')")


def assert_same_footer(page):
    assert page.evaluate("window.loadedIdentity === document.getElementById('page-identity')")
    assert page.locator("#page-identity code").is_visible()


@pytest.mark.parametrize("surface", ["connections", "signin"])
@pytest.mark.parametrize("revision", ["a1" * 20, "b2" * 32, "unknown"])
@pytest.mark.parametrize("interaction", ["keyboard", "touch"])
def test_full_revision_disclosure(browser_page, surface, revision, interaction):
    identity = PageIdentity("Example", "1.2.3", revision)
    markup = (
        connections_page("Example connection", "<p>Connection controls</p>", identity=identity)
        if surface == "connections"
        else render(PageText(identity=identity), None)
    )
    browser = browser_page.context.browser
    page = browser.new_page(
        has_touch=interaction == "touch",
        viewport={"width": 320 if interaction == "touch" else 1280, "height": 720},
    )
    try:
        page.set_content(markup)
        footer = page.locator("footer")
        summary = footer.locator("summary")
        assert summary.count() == 1
        assert f"Example v1.2.3 · {revision[:12]}" in summary.inner_text()
        assert not footer.locator("code").is_visible()
        if interaction == "keyboard":
            for _ in range(20):
                page.keyboard.press("Tab")
                if summary.evaluate("node => node === document.activeElement"):
                    break
            assert summary.evaluate("node => node === document.activeElement")
            page.keyboard.press("Enter")
        else:
            summary.tap()
        code = footer.locator("code")
        assert code.is_visible()
        assert code.inner_text() == revision
        code.click()
        assert page.evaluate("String(getSelection())") == revision
        assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
    finally:
        page.close()


def test_signin_footer_survives_forms_waiting_polls_and_completion(browser_page):
    state = ["ready"]
    reads = []
    text = PageText(
        reconnect=True,
        identity=IDENTITY,
        intro_html='Synthetic account <input id="account-input" name="account">',
    )

    def serve(route):
        path = urlsplit(route.request.url).path
        if path.endswith("/state"):
            reads.append(state[0])
            route.fulfill(content_type="application/json", body=json.dumps({"state": state[0]}))
        elif path.endswith("/start"):
            state[0] = "waiting"
            route.fulfill(content_type="application/json", body=json.dumps({"state": state[0]}))
        elif path.endswith("/novnc/vnc.html"):
            route.fulfill(content_type="text/html", body="<html><body>Synthetic remote viewer</body></html>")
        elif path == "/connect/example":
            route.fulfill(content_type="text/html", body=render(text, "Synthetic account"))
        else:
            route.abort()

    browser_page.clock.install()
    browser_page.route("**/*", serve)
    browser_page.goto("https://app.example/connect/example")
    browser_page.wait_for_function(
        "document.getElementById('account-input') && !document.getElementById('intro').hidden"
    )
    browser_page.locator("#account-input").fill("unfinished draft")
    remember_footer(browser_page)
    browser_page.get_by_role("button", name="Continue to the site's sign-in", exact=True).click()
    browser_page.locator("#view iframe").wait_for()
    browser_page.evaluate("window.loadedFrame = document.querySelector('#view iframe')")
    browser_page.clock.run_for(1600)
    assert reads.count("waiting") >= 2
    assert browser_page.evaluate("window.loadedFrame === document.querySelector('#view iframe')")
    assert browser_page.locator("#account-input").input_value() == "unfinished draft"
    assert_same_footer(browser_page)
    assert not browser_page.frame_locator("#view iframe").locator("#page-identity").count()
    state[0] = "connected"
    browser_page.clock.run_for(1600)
    assert browser_page.get_by_role("heading", name="Connection saved", exact=True).is_visible()
    assert_same_footer(browser_page)


@pytest.mark.parametrize("viewport", [{"width": 390, "height": 720}, {"width": 1280, "height": 860}])
def test_direct_view_footer_survives_remote_view_polls_and_terminal_state(browser_page, tmp_path, viewport):
    window = Window("w" * 24, "desktop", 0, 0.0, 1000.0, state="waiting", host="accounts.example.com")
    windows = Windows(lambda window: None, clock=lambda: 1.0)
    windows._windows[window.id] = window
    app = build_app(windows, token="b" * 40, novnc_dir=tmp_path, identity=IDENTITY)
    client = TestClient(app)
    reads = []

    def serve(route):
        url = urlsplit(route.request.url)
        if url.path == "/novnc/core/rfb.js":
            route.fulfill(
                content_type="text/javascript",
                body="""export default class RFB {
                  constructor(screen, url) {
                    window.rfbCount = (window.rfbCount || 0) + 1;
                    screen.innerHTML = '<input id="remote-input" value="remote draft">';
                  }
                  disconnect() { window.rfbDisconnected = true; }
                }""",
            )
        else:
            if url.path.endswith("/state"):
                reads.append(window.state)
            response = client.get(url.path + ("?" + url.query if url.query else ""))
            route.fulfill(status=response.status_code, headers=dict(response.headers), body=response.content)

    browser_page.set_viewport_size(viewport)
    browser_page.route("**/*", serve)
    browser_page.goto(f"https://app.example/view/{window.id}?t={window.view_token}")
    browser_page.locator("#remote-input").wait_for()
    assert "?t=" not in browser_page.url
    browser_page.locator("#remote-input").fill("unsaved remote input")
    remember_footer(browser_page)
    browser_page.evaluate("window.loadedScreen = document.getElementById('screen')")
    browser_page.wait_for_timeout(2200)
    assert len(reads) >= 3
    assert browser_page.evaluate("window.rfbCount") == 1
    assert browser_page.locator("#remote-input").input_value() == "unsaved remote input"
    assert browser_page.evaluate("window.loadedScreen === document.getElementById('screen')")
    assert_same_footer(browser_page)
    screen = browser_page.locator("#screen").bounding_box()
    status = browser_page.locator("#status").bounding_box()
    footer = browser_page.locator("#page-identity").bounding_box()
    assert screen["height"] > 100
    assert screen["y"] + screen["height"] <= status["y"] + 1
    assert status["y"] + status["height"] <= footer["y"] + 1
    assert footer["y"] + footer["height"] <= viewport["height"] + 1
    window.state = "connected"
    browser_page.wait_for_timeout(1100)
    assert browser_page.get_by_text("Signed in. You can close this page.", exact=True).is_visible()
    assert browser_page.evaluate("window.rfbDisconnected")
    assert_same_footer(browser_page)
    client.close()


def test_delegation_footer_is_selectable_under_its_original_strict_csp(browser_page):
    from signin_window.delegation import _page

    manager = SimpleNamespace(
        config=SimpleNamespace(public_base_url="https://app.example", issuer="https://identity.example.com")
    )
    response = _page(manager, "synthetic-csrf", identity=IDENTITY)
    methods = []

    def serve(route):
        methods.append(route.request.method)
        route.fulfill(status=response.status_code, headers=dict(response.headers), body=response.body)

    browser_page.add_init_script(
        "window.policyViolations = []; document.addEventListener('securitypolicyviolation', "
        "event => window.policyViolations.push(event.violatedDirective));"
    )
    browser_page.route("**/*", serve)
    browser_page.goto("https://app.example/oauth/connect/synthetic-ticket")
    footer = browser_page.locator("#page-identity")
    assert footer.is_visible()
    footer.locator("summary").click()
    assert footer.locator("code").is_visible()
    selected = footer.locator("code").evaluate(
        "node => { const range = document.createRange(); range.selectNodeContents(node); "
        "getSelection().removeAllRanges(); getSelection().addRange(range); return String(getSelection()); }"
    )
    assert selected == IDENTITY.source_revision
    assert browser_page.locator('input[name="csrf"]').first.input_value() == "synthetic-csrf"
    assert browser_page.locator("form").count() == 2
    assert methods == ["GET"]
    assert browser_page.evaluate("window.policyViolations") == []
