"""The link page's script in a real browser: when it opens the window on its own and when it waits for the person.

Runs with the browser group, like ``test_paste_dom.py``: ``uv sync --group browser``, ``uv run playwright install
chromium``, then ``uv run pytest tests/test_page_dom.py``.
"""

import json
from urllib.parse import urlsplit

import pytest

from signin_window.page import PageText, render

sync_api = pytest.importorskip("playwright.sync_api")

LINK = "https://app.example/connect/" + "a" * 32


def visit(text, state="ready"):
    """Load the link page with a stand-in host; returns the POST paths the page sent, in order."""
    posts = []

    def serve(route):
        request, path = route.request, urlsplit(route.request.url).path
        if request.method == "GET" and path == urlsplit(LINK).path:
            route.fulfill(content_type="text/html", body=render(text, "Sam"))
        elif request.method == "GET" and path.endswith("/state"):
            route.fulfill(content_type="application/json", body=json.dumps({"state": state}))
        elif request.method == "POST":
            posts.append(path.rsplit("/", 1)[1])
            route.fulfill(content_type="application/json", body=json.dumps({"state": "starting"}))
        else:
            route.abort()

    with sync_api.sync_playwright() as p:
        try:
            browser = p.chromium.launch(headless=True)
        except Exception as exc:  # browser binary missing
            pytest.skip(f"chromium unavailable: {exc}")
        try:
            page = browser.new_page()
            page.route("**/*", serve)
            page.goto(LINK)
            page.wait_for_timeout(500)
            return posts, page.is_visible("#go")
        finally:
            browser.close()


@pytest.mark.parametrize("reconnect", [False, True])
def test_auto_start_opens_the_window_without_the_intro(reconnect):
    posts, intro = visit(PageText(service="Example", auto_start=True, reconnect=reconnect))
    assert posts == ["start"] and not intro


@pytest.mark.parametrize("reconnect", [False, True])
def test_by_default_the_page_waits_for_the_person(reconnect):
    posts, intro = visit(PageText(service="Example", reconnect=reconnect))
    assert posts == [] and intro


def test_auto_start_resumes_an_active_attempt_instead_of_starting_another():
    posts, intro = visit(PageText(service="Example", auto_start=True, reconnect=True), state="waiting")
    assert posts == [] and not intro


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


def test_shared_connection_refresh_runs_under_exact_csp_and_preserves_focus(browser_page):
    from signin_window.connections import SCRIPT_SOURCE, page

    requests = []

    def serve(route):
        requests.append(route.request.method)
        label = "Signing in" if len(requests) == 1 else "Connection saved"
        body = f'<article><p role="status">{label}</p><button id="stable">Manage connection</button></article>'
        route.fulfill(
            content_type="text/html",
            headers={
                "Content-Security-Policy": f"default-src 'self'; script-src {SCRIPT_SOURCE}; style-src 'unsafe-inline'"
            },
            body=page("Example", body, refresh=len(requests) == 1),
        )

    browser_page.route("**/*", serve)
    browser_page.goto("https://app.example/connections/")
    browser_page.locator("#stable").focus()
    browser_page.get_by_role("status").filter(has_text="Connection saved").wait_for()
    assert browser_page.evaluate("document.activeElement.id") == "stable"
    assert requests == ["GET", "GET"]


def test_refresh_expiry_offers_browser_sign_in_without_automatically_starting_one(browser_page):
    from signin_window.connections import SCRIPT_SOURCE, page

    requests = []

    def serve(route):
        requests.append(route.request.method)
        if len(requests) == 1:
            route.fulfill(
                content_type="text/html",
                headers={"Content-Security-Policy": f"script-src {SCRIPT_SOURCE}"},
                body=page("Example", "<p>Signing in</p>", refresh=True),
            )
        else:
            route.fulfill(status=401, body="Sign-in required")

    browser_page.route("**/*", serve)
    browser_page.goto("https://app.example/connections/")
    link = browser_page.get_by_role("link", name="Sign in to Connections", exact=True)
    link.wait_for()
    assert link.get_attribute("href") == "/connections/login"
    assert requests == ["GET", "GET"]


def test_viewer_initialization_failure_has_visible_recovery_and_no_start(browser_page):
    posts = []

    def serve(route):
        if route.request.method == "POST":
            posts.append(route.request.url)
            route.abort()
        elif urlsplit(route.request.url).path.endswith("/state"):
            route.fulfill(status=503, body="Unavailable")
        else:
            route.fulfill(content_type="text/html", body=render(PageText(reconnect=True, auto_start=True), "Example"))

    browser_page.route("**/*", serve)
    browser_page.goto(LINK)
    browser_page.get_by_role("button", name="Check sign-in status").wait_for()
    assert "could not load" in browser_page.locator("#recovery").inner_text()
    assert posts == []


def test_viewer_expired_session_has_a_connections_exit_without_retrying_start(browser_page):
    def serve(route):
        if urlsplit(route.request.url).path.endswith("/state"):
            route.fulfill(status=401, body="Sign-in required")
        else:
            route.fulfill(
                content_type="text/html",
                body=render(PageText(reconnect=True, auto_start=True, return_url="/connections/"), "Example"),
            )

    browser_page.route("**/*", serve)
    browser_page.goto(LINK)
    browser_page.get_by_role("heading", name="Sign in to Connections again").wait_for()
    assert browser_page.get_by_role("link", name="Back to Connections").get_attribute("href") == "/connections/"


@pytest.mark.parametrize(
    "status,state,heading",
    [(429, "limited", "Too many sign-in attempts"), (404, "unavailable", "This request is unavailable")],
)
def test_viewer_displays_the_applications_refusal_instead_of_a_network_error(browser_page, status, state, heading):
    def serve(route):
        if urlsplit(route.request.url).path.endswith("/state"):
            route.fulfill(status=status, content_type="application/json", body=json.dumps({"state": state}))
        else:
            route.fulfill(content_type="text/html", body=render(PageText(reconnect=True), "Example"))

    browser_page.route("**/*", serve)
    browser_page.goto(LINK)
    browser_page.get_by_role("heading", name=heading, exact=True).wait_for()


def test_recovering_a_waiting_viewer_restores_cancel_and_hides_the_intro(browser_page):
    reads = []

    def serve(route):
        path = urlsplit(route.request.url).path
        if path.endswith("/state"):
            reads.append(path)
            if len(reads) == 1:
                route.fulfill(status=503, body="Unavailable")
            else:
                route.fulfill(content_type="application/json", body='{"state":"waiting"}')
        elif path == urlsplit(LINK).path:
            route.fulfill(content_type="text/html", body=render(PageText(reconnect=True), "Example"))
        else:
            route.abort()

    browser_page.route("**/*", serve)
    browser_page.goto(LINK)
    browser_page.get_by_role("button", name="Check sign-in status").click()
    browser_page.get_by_role("button", name="Cancel sign-in", exact=True).wait_for()
    assert not browser_page.locator("#intro").is_visible()
    assert browser_page.locator("header .bar").is_visible()


def test_status_updates_do_not_erase_unsent_form_changes(browser_page):
    from signin_window.connections import SCRIPT_SOURCE, page

    reads = []

    def serve(route):
        reads.append(route.request.method)
        body = "<p role=status>Signing in</p><input id=choice value=original><input id=consent type=checkbox>"
        route.fulfill(
            content_type="text/html",
            headers={"Content-Security-Policy": f"script-src {SCRIPT_SOURCE}"},
            body=page("Example", body if len(reads) == 1 else "<p role=status>Connection saved</p>", refresh=True),
        )

    browser_page.route("**/*", serve)
    browser_page.goto("https://app.example/connections/")
    browser_page.locator("#choice").fill("my choice")
    browser_page.locator("#consent").check()
    browser_page.wait_for_timeout(2500)
    assert len(reads) >= 2
    assert browser_page.locator("#choice").input_value() == "my choice"
    assert browser_page.locator("#consent").is_checked()


@pytest.mark.parametrize("edited", [False, True])
def test_refresh_compares_selects_to_their_effective_initial_selection(browser_page, edited):
    from signin_window.connections import SCRIPT_SOURCE, page

    reads = []

    def serve(route):
        reads.append(route.request.method)
        body = (
            "<p role=status>Signing in</p><select id=account><option>Personal</option><option>Work</option></select>"
            if len(reads) == 1
            else "<p role=status>Connection saved</p>"
        )
        route.fulfill(
            content_type="text/html",
            headers={"Content-Security-Policy": f"script-src {SCRIPT_SOURCE}"},
            body=page("Example", body, refresh=len(reads) == 1),
        )

    browser_page.route("**/*", serve)
    browser_page.goto("https://app.example/connections/")
    if edited:
        browser_page.locator("select").select_option(label="Work")
        browser_page.wait_for_timeout(2500)
        assert len(reads) >= 2
        assert browser_page.locator("select").input_value() == "Work"
        assert browser_page.get_by_text("Signing in", exact=True).is_visible()
    else:
        browser_page.get_by_text("Connection saved", exact=True).wait_for()


@pytest.mark.parametrize("refused", [False, True])
def test_cancel_displays_application_outcomes(browser_page, refused):
    cancelled = []

    def serve(route):
        path = urlsplit(route.request.url).path
        if path.endswith("/cancel"):
            cancelled.append(True)
            if refused:
                route.fulfill(status=404, content_type="application/json", body='{"state":"unavailable"}')
            else:
                route.fulfill(status=204)
        elif path.endswith("/state"):
            state = "cancelled" if cancelled else "waiting"
            route.fulfill(content_type="application/json", body=json.dumps({"state": state}))
        elif path == urlsplit(LINK).path:
            route.fulfill(content_type="text/html", body=render(PageText(reconnect=True), "Example"))
        else:
            route.abort()

    browser_page.route("**/*", serve)
    browser_page.goto(LINK)
    browser_page.get_by_role("button", name="Cancel sign-in", exact=True).click()
    heading = "This request is unavailable" if refused else "Sign-in cancelled"
    browser_page.get_by_role("heading", name=heading, exact=True).wait_for()


def test_stalled_cancellation_has_bounded_recovery(browser_page):
    def serve(route):
        path = urlsplit(route.request.url).path
        if path.endswith("/cancel"):
            return  # Keep the request pending until the page's timeout aborts it.
        if path.endswith("/state"):
            route.fulfill(content_type="application/json", body='{"state":"waiting"}')
        elif path == urlsplit(LINK).path:
            route.fulfill(content_type="text/html", body=render(PageText(reconnect=True), "Example"))
        else:
            route.abort()

    browser_page.route("**/*", serve)
    browser_page.goto(LINK)
    cancel = browser_page.get_by_role("button", name="Cancel sign-in", exact=True)
    cancel.click()
    browser_page.get_by_text("We could not confirm the cancellation.", exact=False).wait_for(timeout=15000)
    assert cancel.is_enabled()
    browser_page.wait_for_timeout(2500)  # Ordinary waiting polls must not erase uncertain cancellation.
    assert browser_page.get_by_role("button", name="Check sign-in status").is_visible()


@pytest.mark.parametrize(
    "control", ["<select id=stable><option>Personal</option></select>", "<textarea id=stable>Account note</textarea>"]
)
def test_refresh_restores_focus_to_untouched_form_controls(browser_page, control):
    from signin_window.connections import SCRIPT_SOURCE, page

    reads = []

    def serve(route):
        reads.append(route.request.method)
        label = "Signing in" if len(reads) == 1 else "Connection saved"
        route.fulfill(
            content_type="text/html",
            headers={"Content-Security-Policy": f"script-src {SCRIPT_SOURCE}"},
            body=page("Example", f"<p role=status>{label}</p>" + control, refresh=len(reads) == 1),
        )

    browser_page.route("**/*", serve)
    browser_page.goto("https://app.example/connections/")
    browser_page.locator("#stable").focus()
    browser_page.get_by_text("Connection saved", exact=True).wait_for()
    assert browser_page.evaluate("document.activeElement.id") == "stable"


def test_late_cancel_refusal_cannot_replace_a_successful_completion(browser_page):
    cancel_routes = []

    def serve(route):
        path = urlsplit(route.request.url).path
        if path.endswith("/cancel"):
            cancel_routes.append(route)
        elif path.endswith("/state"):
            route.fulfill(
                content_type="application/json", body=json.dumps({"state": "connected" if cancel_routes else "waiting"})
            )
        elif path == urlsplit(LINK).path:
            route.fulfill(content_type="text/html", body=render(PageText(reconnect=True), "Example"))
        else:
            route.abort()

    browser_page.route("**/*", serve)
    browser_page.goto(LINK)
    browser_page.get_by_role("button", name="Cancel sign-in", exact=True).click()
    browser_page.get_by_role("heading", name="Connection saved", exact=True).wait_for()
    cancel_routes[0].fulfill(status=404, content_type="application/json", body='{"state":"unavailable"}')
    browser_page.wait_for_timeout(250)
    assert browser_page.get_by_role("heading", name="Connection saved", exact=True).is_visible()
    assert not browser_page.get_by_text("This request is unavailable", exact=True).count()


@pytest.mark.parametrize("same_name", [False, True])
def test_refresh_restores_the_correct_field_without_ids(browser_page, same_name):
    from signin_window.connections import SCRIPT_SOURCE, page

    reads = []
    name = "first" if same_name else "second"

    def serve(route):
        reads.append(route.request.method)
        label = "Signing in" if len(reads) == 1 else "Connection saved"
        body = (
            f"<p role=status>{label}</p><form action=save><label>First<input name=first></label>"
            f"<label>Second<input name={name}></label></form>"
        )
        route.fulfill(
            content_type="text/html",
            headers={"Content-Security-Policy": f"script-src {SCRIPT_SOURCE}"},
            body=page("Example", body, refresh=len(reads) == 1),
        )

    browser_page.route("**/*", serve)
    browser_page.goto("https://app.example/connections/")
    browser_page.get_by_label("Second").focus()
    browser_page.get_by_text("Connection saved", exact=True).wait_for()
    assert browser_page.get_by_label("Second").evaluate("element => element === document.activeElement")


def test_late_poll_error_cannot_overwrite_completion_from_cancellation(browser_page):
    states, held = [], []

    def serve(route):
        path = urlsplit(route.request.url).path
        if path.endswith("/cancel"):
            route.fulfill(status=204)
        elif path.endswith("/state"):
            states.append(route)
            if len(states) == 2:
                held.append(route)
            else:
                state = "waiting" if len(states) == 1 else "connected"
                route.fulfill(content_type="application/json", body=json.dumps({"state": state}))
        elif path == urlsplit(LINK).path:
            route.fulfill(content_type="text/html", body=render(PageText(reconnect=True), "Example"))
        else:
            route.abort()

    browser_page.route("**/*", serve)
    browser_page.goto(LINK)
    browser_page.wait_for_timeout(1800)  # The regular poll is in flight when cancellation begins.
    assert held
    browser_page.get_by_role("button", name="Cancel sign-in", exact=True).click()
    browser_page.get_by_role("heading", name="Connection saved", exact=True).wait_for()
    held[0].fulfill(status=401, body="Sign-in required")
    browser_page.wait_for_timeout(250)
    assert browser_page.get_by_role("heading", name="Connection saved", exact=True).is_visible()


@pytest.mark.parametrize("prefix", ["", "/app"])
def test_nested_progress_pages_recover_to_the_fixed_application_login(browser_page, prefix):
    from signin_window.connections import SCRIPT_SOURCE, page

    reads = []
    login_url = prefix + "/connections/login"

    def serve(route):
        reads.append(route.request.method)
        if len(reads) > 1:
            route.fulfill(status=401, body="Sign-in required")
        else:
            route.fulfill(
                content_type="text/html",
                headers={"Content-Security-Policy": f"script-src {SCRIPT_SOURCE}"},
                body=page("Example", "<p>Signing in</p>", refresh=True, login_url=login_url),
            )

    browser_page.route("**/*", serve)
    browser_page.goto("https://app.example" + prefix + "/connections/accounts/example/")
    link = browser_page.get_by_role("link", name="Sign in to Connections", exact=True)
    link.wait_for()
    assert link.get_attribute("href") == login_url


@pytest.mark.parametrize("scheme", ["light", "dark"])
def test_connection_shell_fits_a_small_screen_with_enlarged_text(browser_page, scheme):
    from signin_window.connections import page

    browser_page.set_viewport_size({"width": 320, "height": 900})
    browser_page.emulate_media(color_scheme=scheme)
    browser_page.set_content(
        page(
            "Google Photos connection",
            '<article><h2>Your Google account</h2><p role="status">Connection saved</p>'
            "<p>Account: reader.with.a.long.name@example.com</p>"
            '<form><button class="secondary" type="button">Reconnect Google Photos</button></form></article>',
        )
    )
    browser_page.add_style_tag(content=":root{font-size:32px}")
    assert browser_page.evaluate("document.documentElement.scrollWidth <= innerWidth")
    assert browser_page.locator("button").bounding_box()["height"] >= 44
