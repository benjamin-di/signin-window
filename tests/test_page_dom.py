"""The link page's script in a real browser: when it opens the window on its own and when it waits for the person.

Runs with the browser group, like ``test_paste_dom.py``: ``uv sync --group browser``, ``uv run playwright install
chromium``, then ``uv run pytest tests/test_page_dom.py``.
"""

import json
from urllib.parse import urlsplit

import pytest

from signin_window.connections import PageIdentity
from signin_window.page import PageText, render

sync_api = pytest.importorskip("playwright.sync_api")

LINK = "https://app.example/connect/" + "a" * 32


def visit(browser_page, text, state="ready"):
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

    browser_page.route("**/*", serve)
    browser_page.goto(LINK)
    browser_page.wait_for_timeout(500)
    return posts, browser_page.is_visible("#go")


@pytest.mark.parametrize("reconnect", [False, True])
def test_auto_start_opens_the_window_without_the_intro(browser_page, reconnect):
    posts, intro = visit(browser_page, PageText(service="Example", auto_start=True, reconnect=reconnect))
    assert posts == ["start"] and not intro


@pytest.mark.parametrize("reconnect", [False, True])
def test_by_default_the_page_waits_for_the_person(browser_page, reconnect):
    posts, intro = visit(browser_page, PageText(service="Example", reconnect=reconnect))
    assert posts == [] and intro


def test_auto_start_resumes_an_active_attempt_instead_of_starting_another(browser_page):
    posts, intro = visit(browser_page, PageText(service="Example", auto_start=True, reconnect=True), state="waiting")
    assert posts == [] and not intro


def test_waiting_page_gives_the_viewer_space_and_keeps_help_on_demand(browser_page):
    def serve(route):
        if route.request.url == LINK:
            route.fulfill(
                content_type="text/html",
                body=render(PageText(service="Example", reconnect=True, auto_start=True), "Example"),
            )
        elif route.request.url.endswith("/state"):
            route.fulfill(content_type="application/json", body=json.dumps({"state": "waiting", "host": "example.com"}))
        else:
            route.abort()

    browser_page.set_viewport_size({"width": 390, "height": 844})
    browser_page.route("**/*", serve)
    browser_page.goto(LINK)
    browser_page.locator("iframe").wait_for()
    assert browser_page.locator("header").bounding_box()["height"] < 80
    assert browser_page.locator("iframe").bounding_box()["height"] > 700
    assert browser_page.locator("#signin-help").evaluate("e => e.open") is False
    browser_page.get_by_text("?", exact=True).click()
    assert browser_page.locator("#signin-help").evaluate("e => e.open") is True
    browser_page.get_by_role("button", name="Cancel sign-in", exact=True).wait_for()


@pytest.mark.parametrize("initial", ["waiting", "saving"])
def test_saving_disposes_the_viewer_and_keeps_progress_readable(browser_page, initial):
    state = {"value": initial}

    def serve(route):
        if route.request.url == LINK:
            route.fulfill(content_type="text/html", body=render(PageText(service="Example", auto_start=True), "Sam"))
        elif route.request.url.endswith("/state"):
            route.fulfill(content_type="application/json", body=json.dumps({"state": state["value"]}))
        else:
            route.abort()

    browser_page.route("**/*", serve)
    browser_page.goto(LINK)
    if initial == "waiting":
        browser_page.locator("iframe").wait_for()
    state["value"] = "saving"
    browser_page.wait_for_function("document.getElementById('status').textContent.includes('Saving')")
    assert browser_page.locator("iframe").count() == 0
    status = browser_page.locator("#status")
    assert status.bounding_box()["height"] > 12
    assert status.evaluate("e => getComputedStyle(e).clipPath") == "none"
    state["value"] = "connected"
    browser_page.get_by_role("heading", name="Connection saved").wait_for()
    assert browser_page.locator("iframe").count() == 0


@pytest.fixture(scope="module")
def _chromium_browser():
    with sync_api.sync_playwright() as driver:
        try:
            browser = driver.chromium.launch(headless=True)
        except Exception as exc:
            pytest.skip(f"chromium unavailable: {exc}")
        try:
            yield browser
        finally:
            browser.close()


@pytest.fixture
def browser_page(_chromium_browser):
    context = _chromium_browser.new_context()
    try:
        yield context.new_page()
    finally:
        context.close()


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
            body=page(
                "Example",
                body,
                refresh=len(requests) == 1,
                identity=PageIdentity("Example", "1.2.3", "abcdef1234567890"),
            ),
        )

    browser_page.route("**/*", serve)
    browser_page.goto("https://app.example/connections/")
    browser_page.locator("#stable").focus()
    browser_page.get_by_role("status").filter(has_text="Connection saved").wait_for()
    assert browser_page.evaluate("document.activeElement.id") == "stable"
    assert requests == ["GET", "GET"]


@pytest.mark.parametrize(
    "next_identity",
    [
        PageIdentity("Other service", "1.2.3", "abcdef1234567890"),
        PageIdentity("Example", "1.2.4", "abcdef1234567890"),
        PageIdentity("Example", "1.2.3", "abcdef1234569999"),
        None,
    ],
    ids=["service", "version", "full-revision", "removed"],
)
@pytest.mark.parametrize("edited", [False, True])
def test_build_change_keeps_the_loaded_shell_and_form_and_stops_polling(browser_page, next_identity, edited):
    from signin_window.connections import SCRIPT_SOURCE, page

    reads = []
    original_identity = PageIdentity("Example", "1.2.3", "abcdef1234567890")

    def serve(route):
        reads.append(route.request.method)
        first = len(reads) == 1
        route.fulfill(
            content_type="text/html",
            headers={"Content-Security-Policy": f"script-src {SCRIPT_SOURCE}"},
            body=page(
                "Original shell" if first else "New shell",
                '<form action="/connections/save"><input id="choice" value="original"></form>'
                if first
                else "<p>New build content</p>",
                refresh=True,
                identity=original_identity if first else next_identity,
            ),
        )

    browser_page.clock.install()
    browser_page.route("**/*", serve)
    browser_page.goto("https://app.example/connections/")
    browser_page.locator("#choice").focus()
    if edited:
        browser_page.locator("#choice").fill("unsent choice")
    browser_page.evaluate("window.originalForm = document.querySelector('form')")
    browser_page.clock.run_for(2100)
    link = browser_page.get_by_role("link", name="Reload page", exact=True)
    link.wait_for()
    assert link.get_attribute("href") == "https://app.example/connections/"
    assert browser_page.get_by_role("heading", name="Original shell", exact=True).is_visible()
    assert browser_page.locator("#choice").input_value() == ("unsent choice" if edited else "original")
    assert browser_page.evaluate("document.querySelector('form') === window.originalForm")
    assert browser_page.evaluate("document.activeElement.id") == "choice"
    footer = browser_page.locator("#connection-identity")
    assert footer.inner_text() == "Example v1.2.3 · abcdef123456"
    assert footer.get_attribute("data-source-revision") == original_identity.source_revision
    assert browser_page.locator("#connection-content").get_attribute("data-refresh") is None
    browser_page.clock.run_for(2300)
    assert reads == ["GET", "GET"]


@pytest.mark.parametrize("next_build", ["same", "changed"])
def test_transient_non_connections_response_retries_before_comparing_builds(browser_page, next_build):
    from signin_window.connections import SCRIPT_SOURCE, page

    reads = []
    original_identity = PageIdentity("Example", "1.2.3", "abcdef1234567890")
    next_identity = original_identity if next_build == "same" else PageIdentity("Example", "1.2.4", "abcdef1234569999")

    def serve(route):
        reads.append(route.request.method)
        if len(reads) == 1:
            body = page(
                "Original shell",
                '<form action="/connections/save"><input id="choice" value="original"></form>'
                '<p role="status">Pending</p>',
                refresh=True,
                identity=original_identity,
            )
        elif len(reads) == 2:
            body = "<!doctype html><html><body><p>Temporarily unavailable</p></body></html>"
        else:
            body = page("Next shell", '<p role="status">Connection saved</p>', identity=next_identity)
        route.fulfill(
            content_type="text/html", headers={"Content-Security-Policy": f"script-src {SCRIPT_SOURCE}"}, body=body
        )

    def advance(milliseconds):
        for _ in range(milliseconds // 500):
            browser_page.clock.run_for(500)
            browser_page.wait_for_timeout(25)

    browser_page.clock.install()
    browser_page.route("**/*", serve)
    browser_page.goto("https://app.example/connections/")
    if next_build == "changed":
        browser_page.locator("#choice").fill("unsent choice")
    browser_page.evaluate("window.originalForm = document.querySelector('form')")
    advance(16000)
    assert reads == ["GET", "GET", "GET"]
    content = browser_page.locator("#connection-content")
    assert content.get_attribute("data-refresh") is None
    if next_build == "same":
        assert browser_page.locator("#connection-notice").is_hidden()
        assert browser_page.get_by_role("status").filter(has_text="Connection saved").is_visible()
    else:
        assert browser_page.get_by_role("link", name="Reload page", exact=True).is_visible()
        assert browser_page.get_by_role("heading", name="Original shell", exact=True).is_visible()
        assert browser_page.locator("#choice").input_value() == "unsent choice"
        assert browser_page.evaluate("document.querySelector('form') === window.originalForm")
        footer = browser_page.locator("#connection-identity")
        assert footer.get_attribute("data-source-revision") == original_identity.source_revision
    advance(10000)
    assert reads == ["GET", "GET", "GET"]


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
    assert browser_page.get_by_role("heading", level=1).is_visible()


def test_status_updates_do_not_erase_unsent_form_changes(browser_page):
    from signin_window.connections import SCRIPT_SOURCE, page

    reads = []

    def serve(route):
        reads.append(route.request.method)
        body = "<p role=status>Signing in</p><input id=choice value=original><input id=consent type=checkbox>"
        route.fulfill(
            content_type="text/html",
            headers={"Content-Security-Policy": f"script-src {SCRIPT_SOURCE}"},
            body=page(
                "Example",
                body if len(reads) == 1 else "<p role=status>Connection saved</p>",
                refresh=True,
                identity=PageIdentity("Example", "1.2.3", "abcdef1234567890"),
            ),
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

    browser_page.clock.install()
    browser_page.route("**/*", serve)
    browser_page.goto(LINK)
    cancel = browser_page.get_by_role("button", name="Cancel sign-in", exact=True)
    cancel.click()
    browser_page.clock.run_for(10100)
    browser_page.get_by_text("We could not confirm the cancellation.", exact=False).wait_for(timeout=5000)
    assert cancel.is_enabled()
    browser_page.clock.run_for(2500)  # Ordinary waiting polls must not erase uncertain cancellation.
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


@pytest.mark.parametrize("width", [320, 390, 1280])
@pytest.mark.parametrize("scheme", ["light", "dark"])
def test_connection_actions_remain_accessible_and_consistent_at_phone_widths(browser_page, width, scheme):
    from signin_window.connections import page

    browser_page.set_viewport_size({"width": width, "height": 844})
    browser_page.emulate_media(color_scheme=scheme)
    browser_page.set_content(
        page(
            "Example connection",
            """
        <article><h2>Example provider</h2><p role="status">Connection saved</p>
        <a class="button" href="/connections/login">Verify and reconnect</a>
        <form method="post" action="/connections/start"><button>Reconnect</button></form>
        <label><input type="checkbox" name="capability">Share with this person</label>
        </article>""",
        )
    )
    link = browser_page.get_by_role("link", name="Verify and reconnect")
    button = browser_page.get_by_role("button", name="Reconnect", exact=True)
    assert link.bounding_box()["height"] >= 44
    assert button.bounding_box()["height"] >= 44
    if width <= 480:
        assert abs(link.bounding_box()["width"] - button.bounding_box()["width"]) < 1
    assert browser_page.locator("label").bounding_box()["height"] >= 44
    assert browser_page.evaluate("document.documentElement.scrollWidth <= innerWidth")
    assert browser_page.locator("html").evaluate("el => getComputedStyle(el).backgroundColor") == (
        "rgb(13, 14, 16)" if scheme == "dark" else "rgb(246, 245, 242)"
    )
    browser_page.keyboard.press("Tab")
    assert link.evaluate("el => document.activeElement === el")
    assert link.evaluate("el => getComputedStyle(el).outlineWidth") == "3px"


def test_notice_and_layout_mismatch_switcher_restart_into_current_layout(browser_page):
    state = {"state": "waiting", "host": "auth.example.com", "layout": "phone"}
    events = []

    def serve(route):
        path = urlsplit(route.request.url).path
        if path == urlsplit(LINK).path:
            route.fulfill(
                content_type="text/html",
                body=render(
                    PageText(
                        service="Example",
                        reconnect=True,
                        auto_start=True,
                        notice="Use SMS or password — passkeys unavailable here.",
                    ),
                    "Sam",
                ),
            )
        elif path.endswith("/state"):
            route.fulfill(content_type="application/json", body=json.dumps(state))
        elif path.endswith("/cancel"):
            events.append(("cancel", None))
            state["state"] = "cancelled"
            state.pop("layout", None)
            route.fulfill(status=204)
        elif path.endswith("/start"):
            body = json.loads(route.request.post_data or "{}")
            events.append(("start", body.get("layout")))
            state["state"] = "waiting"
            state["layout"] = body.get("layout")
            route.fulfill(content_type="application/json", body=json.dumps(state))
        else:
            route.abort()

    browser_page.set_viewport_size({"width": 1280, "height": 860})
    browser_page.route("**/*", serve)
    browser_page.goto(LINK)
    browser_page.locator("iframe").wait_for()
    iframe_src = browser_page.locator("iframe").get_attribute("src")
    assert "quality=8" in iframe_src and "show_dot=0" in iframe_src
    assert browser_page.locator("#notice").is_visible()
    assert "passkeys unavailable" in browser_page.locator("#notice").inner_text()
    switch_btn = browser_page.get_by_role("button", name="Switch to desktop view", exact=True)
    switch_btn.wait_for()
    assert "mobile view" in browser_page.locator("#layout-mismatch-text").inner_text()
    switch_btn.click()
    browser_page.locator("iframe").wait_for()
    assert browser_page.locator("#layout-mismatch").is_hidden()
    assert events == [("cancel", None), ("start", "desktop")]
    # Header Restart button cleanly cancels and starts again.
    browser_page.get_by_role("button", name="Restart sign-in", exact=True).click()
    browser_page.locator("iframe").wait_for()
    assert events == [("cancel", None), ("start", "desktop"), ("cancel", None), ("start", "desktop")]
    # Finishing hides the notice bar.
    state["state"] = "connected"
    browser_page.get_by_role("heading", name="Connection saved", exact=True).wait_for()
    assert browser_page.locator("#notice").is_hidden()


def test_restart_preserves_completion_if_signin_finished_during_cancel(browser_page):
    starts = []

    def serve(route):
        path = urlsplit(route.request.url).path
        if path == urlsplit(LINK).path:
            route.fulfill(content_type="text/html", body=render(PageText(reconnect=True), "Sam"))
        elif path.endswith("/cancel"):
            route.fulfill(status=204)
        elif path.endswith("/state"):
            route.fulfill(
                content_type="application/json",
                body=json.dumps({"state": "connected" if starts else "waiting", "layout": "desktop"}),
            )
        elif path.endswith("/start"):
            starts.append("start")
            route.fulfill(content_type="application/json", body=json.dumps({"state": "starting"}))
        else:
            route.abort()

    browser_page.route("**/*", serve)
    browser_page.goto(LINK)
    browser_page.locator("iframe").wait_for()
    starts.append("cancel-next")
    browser_page.get_by_role("button", name="Restart sign-in", exact=True).click()
    browser_page.get_by_role("heading", name="Connection saved", exact=True).wait_for()
    assert "start" not in starts


def test_stale_poll_response_cannot_cancel_a_completed_restart(browser_page):
    held = []
    phase = {"step": "initial"}

    def serve(route):
        path = urlsplit(route.request.url).path
        if path == urlsplit(LINK).path:
            route.fulfill(content_type="text/html", body=render(PageText(reconnect=True), "Sam"))
        elif path.endswith("/cancel"):
            phase["step"] = "cancelled"
            route.fulfill(status=204)
        elif path.endswith("/start"):
            phase["step"] = "restarted"
            route.fulfill(
                content_type="application/json",
                body=json.dumps({"state": "waiting", "layout": "desktop", "can_restart": True}),
            )
        elif path.endswith("/state"):
            if phase["step"] == "initial":
                phase["step"] = "hold_next"
                route.fulfill(
                    content_type="application/json",
                    body=json.dumps({"state": "waiting", "layout": "desktop", "can_restart": True}),
                )
            elif phase["step"] == "hold_next":
                held.append(route)
            elif phase["step"] == "cancelled":
                route.fulfill(content_type="application/json", body=json.dumps({"state": "cancelled"}))
            else:
                route.fulfill(
                    content_type="application/json",
                    body=json.dumps({"state": "waiting", "layout": "desktop", "can_restart": True}),
                )
        else:
            route.abort()

    browser_page.route("**/*", serve)
    browser_page.goto(LINK)
    browser_page.locator("iframe").wait_for()
    browser_page.wait_for_timeout(1700)
    assert held
    browser_page.get_by_role("button", name="Restart sign-in", exact=True).click()
    browser_page.locator("iframe").wait_for()
    # Release the stale pre-restart poll as cancelled; the replacement viewer must survive.
    held[0].fulfill(content_type="application/json", body=json.dumps({"state": "cancelled"}))
    browser_page.wait_for_timeout(250)
    assert browser_page.locator("iframe").count() == 1
    assert browser_page.locator("#done").is_hidden()


def test_restart_respects_can_restart_budget_and_before_start_hook(browser_page):
    events = []
    hook_js = (
        "window.beforeCalls = 0; "
        "window.signinBeforeStart = async () => { window.beforeCalls++; return window.allowBeforeStart; };"
    )

    def serve(route):
        path = urlsplit(route.request.url).path
        if path == urlsplit(LINK).path:
            route.fulfill(
                content_type="text/html",
                body=render(PageText(reconnect=True, script_extra=hook_js), "Sam"),
            )
        elif path.endswith("/state"):
            route.fulfill(
                content_type="application/json",
                body=json.dumps({"state": "waiting", "layout": "phone", "can_restart": False}),
            )
        else:
            if route.request.method == "POST":
                events.append(path)
            route.abort()

    browser_page.set_viewport_size({"width": 1280, "height": 860})
    browser_page.route("**/*", serve)
    browser_page.goto(LINK)
    browser_page.locator("iframe").wait_for()
    assert browser_page.get_by_role("button", name="Restart sign-in", exact=True).is_hidden()
    assert browser_page.locator("#layout-mismatch").is_hidden()

    # Now allow restart but decline via signinBeforeStart: must not cancel the active window.
    browser_page.unroute("**/*")

    def serve_allowed(route):
        path = urlsplit(route.request.url).path
        if path == urlsplit(LINK).path:
            route.fulfill(
                content_type="text/html",
                body=render(
                    PageText(reconnect=True, script_extra="window.allowBeforeStart = false; " + hook_js), "Sam"
                ),
            )
        elif path.endswith("/state"):
            route.fulfill(
                content_type="application/json",
                body=json.dumps({"state": "waiting", "layout": "phone", "can_restart": True}),
            )
        else:
            if route.request.method == "POST":
                events.append(path)
            route.fulfill(status=204)

    browser_page.route("**/*", serve_allowed)
    browser_page.goto(LINK)
    browser_page.locator("iframe").wait_for()
    browser_page.get_by_role("button", name="Restart sign-in", exact=True).click()
    browser_page.wait_for_timeout(150)
    assert browser_page.evaluate("window.beforeCalls") == 1
    assert events == []
    assert browser_page.locator("iframe").count() == 1


def test_deferred_cancellation_keeps_viewer_detached_and_starts_once_cancelled(browser_page):
    calls = []
    cancel_polls = {"n": 0}

    def serve(route):
        path = urlsplit(route.request.url).path
        if path == urlsplit(LINK).path:
            route.fulfill(content_type="text/html", body=render(PageText(reconnect=True), "Sam"))
        elif path.endswith("/cancel"):
            calls.append("cancel")
            cancel_polls["n"] = 1
            route.fulfill(status=204)
        elif path.endswith("/start"):
            calls.append("start")
            cancel_polls["n"] = 99
            route.fulfill(
                content_type="application/json",
                body=json.dumps({"state": "waiting", "layout": "desktop", "can_restart": True}),
            )
        elif path.endswith("/state"):
            if cancel_polls["n"] == 0:
                route.fulfill(
                    content_type="application/json",
                    body=json.dumps({"state": "waiting", "layout": "desktop", "can_restart": True}),
                )
            elif cancel_polls["n"] == 1:
                cancel_polls["n"] = 2
                route.fulfill(
                    content_type="application/json",
                    body=json.dumps({"state": "waiting", "layout": "desktop", "closing": True, "can_restart": True}),
                )
            elif cancel_polls["n"] == 2:
                cancel_polls["n"] = 3
                route.fulfill(content_type="application/json", body=json.dumps({"state": "cancelled"}))
            else:
                route.fulfill(
                    content_type="application/json",
                    body=json.dumps({"state": "waiting", "layout": "desktop", "can_restart": True}),
                )
        else:
            route.abort()

    browser_page.route("**/*", serve)
    browser_page.goto(LINK)
    browser_page.locator("iframe").wait_for()
    browser_page.get_by_role("button", name="Restart sign-in", exact=True).click()
    browser_page.wait_for_timeout(300)
    assert browser_page.locator("iframe").count() == 0
    browser_page.locator("iframe").wait_for(timeout=5000)
    assert calls == ["cancel", "start"]


def test_restart_double_click_runs_before_start_once_and_preserves_host_outcomes(browser_page):
    # 1. Double-clicking Restart while signinBeforeStart is pending invokes the hook once.
    calls = []

    def serve(route):
        path = urlsplit(route.request.url).path
        if path == urlsplit(LINK).path:
            hook = (
                "window.beforeCalls = 0; "
                "window.signinBeforeStart = () => { window.beforeCalls++; "
                "return new Promise(r => { window.resolveBefore = r; }); };"
            )
            route.fulfill(
                content_type="text/html",
                body=render(
                    PageText(reconnect=True, script_extra=hook).with_outcomes(wrong_account="<h1>Wrong account</h1>"),
                    "Sam",
                ),
            )
        elif path.endswith("/cancel"):
            calls.append("cancel")
            route.fulfill(content_type="application/json", body=json.dumps({"state": "wrong_account"}))
        elif path.endswith("/start"):
            calls.append("start")
            route.fulfill(content_type="application/json", body=json.dumps({"state": "starting"}))
        elif path.endswith("/state"):
            route.fulfill(
                content_type="application/json",
                body=json.dumps({"state": "waiting", "layout": "desktop", "can_restart": True}),
            )
        else:
            route.abort()

    browser_page.route("**/*", serve)
    browser_page.goto(LINK)
    browser_page.locator("iframe").wait_for()
    btn = browser_page.get_by_role("button", name="Restart sign-in", exact=True)
    btn.click()
    btn.click(force=True)
    assert browser_page.evaluate("window.beforeCalls") == 1
    # 2. If cancel races with a host-defined terminal outcome (wrong_account), display it instead of restarting.
    browser_page.evaluate("window.resolveBefore(true)")
    browser_page.get_by_role("heading", name="Wrong account", exact=True).wait_for()
    assert calls == ["cancel"]


def test_pre_cancel_stale_poll_does_not_reattach_viewer_after_closing(browser_page):
    held = []
    phase = {"step": 0}

    def serve(route):
        path = urlsplit(route.request.url).path
        if path == urlsplit(LINK).path:
            route.fulfill(content_type="text/html", body=render(PageText(reconnect=True), "Sam"))
        elif path.endswith("/cancel"):
            phase["step"] = 2
            route.fulfill(status=204)
        elif path.endswith("/state"):
            if phase["step"] == 0:
                phase["step"] = 1
                route.fulfill(
                    content_type="application/json",
                    body=json.dumps({"state": "waiting", "layout": "desktop", "can_restart": True}),
                )
            elif phase["step"] == 1:
                held.append(route)
            else:
                route.fulfill(
                    content_type="application/json",
                    body=json.dumps({"state": "waiting", "layout": "desktop", "closing": True, "can_restart": True}),
                )
        else:
            route.abort()

    browser_page.route("**/*", serve)
    browser_page.goto(LINK)
    browser_page.locator("iframe").wait_for()
    browser_page.wait_for_timeout(1700)
    assert held
    browser_page.get_by_role("button", name="Cancel sign-in", exact=True).click()
    browser_page.wait_for_function("() => document.querySelectorAll('iframe').length === 0")
    # Releasing the stale pre-cancel 'waiting' poll must not reattach the iframe or Restart button.
    held[0].fulfill(
        content_type="application/json",
        body=json.dumps({"state": "waiting", "layout": "desktop", "can_restart": True}),
    )
    browser_page.wait_for_timeout(200)
    assert browser_page.locator("iframe").count() == 0
    assert browser_page.get_by_role("button", name="Restart sign-in", exact=True).is_hidden()


def test_deferred_restart_completes_after_recovery_check(browser_page):
    calls = []
    phase = {"step": 0}

    def serve(route):
        path = urlsplit(route.request.url).path
        if path == urlsplit(LINK).path:
            route.fulfill(content_type="text/html", body=render(PageText(reconnect=True), "Sam"))
        elif path.endswith("/cancel"):
            calls.append("cancel")
            phase["step"] = 1
            route.fulfill(
                content_type="application/json",
                body=json.dumps({"state": "waiting", "layout": "desktop", "closing": True, "can_restart": True}),
            )
        elif path.endswith("/start"):
            calls.append("start")
            phase["step"] = 3
            route.fulfill(
                content_type="application/json",
                body=json.dumps({"state": "waiting", "layout": "desktop", "can_restart": True}),
            )
        elif path.endswith("/state"):
            if phase["step"] == 0:
                route.fulfill(
                    content_type="application/json",
                    body=json.dumps({"state": "waiting", "layout": "desktop", "can_restart": True}),
                )
            elif phase["step"] == 1:
                phase["step"] = 2
                route.fulfill(status=503, body="busy")
            elif phase["step"] == 2:
                route.fulfill(content_type="application/json", body=json.dumps({"state": "cancelled"}))
            else:
                route.fulfill(
                    content_type="application/json",
                    body=json.dumps({"state": "waiting", "layout": "desktop", "can_restart": True}),
                )
        else:
            route.abort()

    browser_page.route("**/*", serve)
    browser_page.goto(LINK)
    browser_page.locator("iframe").wait_for()
    browser_page.get_by_role("button", name="Restart sign-in", exact=True).click()
    check_btn = browser_page.get_by_role("button", name="Check sign-in status", exact=True)
    check_btn.wait_for(timeout=5000)
    check_btn.click()
    browser_page.locator("iframe").wait_for(timeout=5000)
    assert calls == ["cancel", "start"]


def test_stale_waiting_poll_does_not_reattach_viewer_after_entering_saving(browser_page):
    held = []
    phase = {"step": 0}

    def serve(route):
        path = urlsplit(route.request.url).path
        if path == urlsplit(LINK).path:
            route.fulfill(content_type="text/html", body=render(PageText(reconnect=True), "Sam"))
        elif path.endswith("/cancel"):
            phase["step"] = 2
            route.fulfill(status=204)
        elif path.endswith("/state"):
            if phase["step"] == 0:
                phase["step"] = 1
                route.fulfill(
                    content_type="application/json",
                    body=json.dumps({"state": "waiting", "layout": "desktop", "can_restart": True}),
                )
            elif phase["step"] == 1:
                held.append(route)
            else:
                route.fulfill(content_type="application/json", body=json.dumps({"state": "saving"}))
        else:
            route.abort()

    browser_page.route("**/*", serve)
    browser_page.goto(LINK)
    browser_page.locator("iframe").wait_for()
    browser_page.wait_for_timeout(1700)
    assert held
    browser_page.get_by_role("button", name="Cancel sign-in", exact=True).click()
    browser_page.wait_for_function("() => document.getElementById('status').textContent.includes('Saving')")
    assert browser_page.locator("iframe").count() == 0
    # Releasing the pre-cancel/pre-saving 'waiting' response must not reattach the iframe.
    held[0].fulfill(
        content_type="application/json",
        body=json.dumps({"state": "waiting", "layout": "desktop", "can_restart": True}),
    )
    browser_page.wait_for_timeout(200)
    assert browser_page.locator("iframe").count() == 0


def test_lost_cancel_response_still_restarts_and_live_replacement_clears_pending_restart(browser_page):
    # 1. Cancel fails with 503, recovery observes closing then cancelled -> sends /start once.
    calls = []
    after_cancel = iter(
        [
            {"state": "waiting", "layout": "desktop", "closing": True, "can_restart": True},
            {"state": "cancelled"},
            {"state": "waiting", "layout": "desktop", "can_restart": True},
        ]
    )

    def serve_lost(route):
        path = urlsplit(route.request.url).path
        if path == urlsplit(LINK).path:
            route.fulfill(content_type="text/html", body=render(PageText(reconnect=True), "Sam"))
        elif path.endswith("/cancel"):
            calls.append("cancel")
            route.fulfill(status=503, body="lost")
        elif path.endswith("/start"):
            calls.append("start")
            route.fulfill(
                content_type="application/json",
                body=json.dumps({"state": "waiting", "layout": "desktop", "can_restart": True}),
            )
        elif path.endswith("/state"):
            body = (
                {"state": "waiting", "layout": "desktop", "can_restart": True}
                if not calls
                else next(after_cancel, {"state": "waiting", "layout": "desktop", "can_restart": True})
            )
            route.fulfill(content_type="application/json", body=json.dumps(body))
        else:
            route.abort()

    browser_page.route("**/*", serve_lost)
    browser_page.goto(LINK)
    browser_page.locator("iframe").wait_for()
    browser_page.get_by_role("button", name="Restart sign-in", exact=True).click()
    check_btn = browser_page.get_by_role("button", name="Check sign-in status", exact=True)
    check_btn.wait_for(timeout=5000)
    check_btn.click()
    browser_page.locator("iframe").wait_for(timeout=5000)
    assert calls == ["cancel", "start"]

    # 2. Cancel fails, recovery finds non-closing waiting -> clears pendingRestart so a later cancelled does NOT start.
    browser_page.unroute("**/*")
    calls2 = []
    after_cancel2 = iter(
        [
            {"state": "waiting", "layout": "desktop", "can_restart": True},
            {"state": "cancelled"},
        ]
    )

    def serve_live(route):
        path = urlsplit(route.request.url).path
        if path == urlsplit(LINK).path:
            route.fulfill(content_type="text/html", body=render(PageText(reconnect=True), "Sam"))
        elif path.endswith("/cancel"):
            calls2.append("cancel")
            route.fulfill(status=503, body="lost")
        elif path.endswith("/start"):
            calls2.append("start")
            route.fulfill(content_type="application/json", body=json.dumps({"state": "starting"}))
        elif path.endswith("/state"):
            body = (
                {"state": "waiting", "layout": "desktop", "can_restart": True}
                if not calls2
                else next(after_cancel2, {"state": "cancelled"})
            )
            route.fulfill(content_type="application/json", body=json.dumps(body))
        else:
            route.abort()

    browser_page.route("**/*", serve_live)
    browser_page.goto(LINK)
    browser_page.locator("iframe").wait_for()
    browser_page.get_by_role("button", name="Restart sign-in", exact=True).click()
    check_btn = browser_page.get_by_role("button", name="Check sign-in status", exact=True)
    check_btn.wait_for(timeout=5000)
    check_btn.click()
    browser_page.get_by_role("heading", name="Sign-in cancelled", exact=True).wait_for(timeout=5000)
    assert calls2 == ["cancel"]
