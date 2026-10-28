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
