"""Trusted touch checks; software-keyboard opening still needs a physical phone."""

from urllib.parse import urlsplit

import pytest
from test_paste_dom import ADD_ON, MODULES, VIEWER

sync_api = pytest.importorskip("playwright.sync_api")


@pytest.mark.parametrize("engine", ["chromium", "webkit"])
def test_touch_paste_and_controls_preserve_native_editor(engine):
    html = VIEWER
    if engine == "chromium":
        start = html.index('  Object.defineProperty(navigator, "clipboard", {')
        end = html.index("  UI.rfb = {", start)
        html = html[:start] + html[end:]
        copy = "navigator.clipboard.writeText('SyntheticPaste9!').then(() => this.textContent='Copied')"
    else:
        # Linux headless WebKit cannot approve a clipboard read. Keep the existing
        # clipboard stand-in, but use real touch events rather than DOM clicks.
        copy = "document.documentElement.dataset.clipboard='SyntheticPaste9!';this.textContent='Copied'"
    html = html.replace("<head>", '<head><meta name="viewport" content="width=device-width,initial-scale=1">')
    html = html.replace("viewOnly: false,", "viewOnly: false, focusOnClick: true,")
    html = html.replace(
        "<body></body>",
        f"""<body><div id=noVNC_container><canvas width=500 height=900 tabindex=0></canvas></div>
        <button id=copy style="position:fixed;top:10px;left:10px;z-index:20"
          onclick="{copy}">
          Copy test text</button></body>""",
    )
    files = {"/vnc.html": ("text/html", html), "/paste.js": ("text/javascript", ADD_ON.read_text())}
    files.update({path: ("text/javascript", body) for path, body in MODULES.items()})

    def serve(route):
        url = urlsplit(route.request.url)
        found = files.get(url.path) if url.netloc == "viewer.example" else None
        if found:
            route.fulfill(content_type=found[0], body=found[1])
        else:
            route.abort()

    with sync_api.sync_playwright() as p:
        browser = getattr(p, engine).launch(headless=True)
        try:
            context = browser.new_context(viewport={"width": 390, "height": 844}, has_touch=True, is_mobile=True)
            if engine == "chromium":
                context.grant_permissions(["clipboard-read", "clipboard-write"])
            page = context.new_page()
            page.route("**/*", serve)
            page.goto("https://viewer.example/vnc.html")
            page.get_by_role("button", name="Copy test text", exact=True).tap()
            page.get_by_role("button", name="Copied", exact=True).wait_for()
            page.get_by_role("button", name="Keyboard", exact=True).tap()
            editor = page.locator("#signin_input")
            assert editor.evaluate("e => document.activeElement === e")
            for count in (1, 2):
                page.get_by_role("button", name="Paste", exact=True).tap()
                page.wait_for_function(
                    "text => document.documentElement.dataset.typed === text",
                    arg="SyntheticPaste9!" * count,
                    timeout=3000,
                )
                assert editor.evaluate("e => document.activeElement === e")
                assert editor.input_value() == "_"
                assert page.locator("#signin_feedback").inner_text() == ""
            page.get_by_role("button", name="Zoom", exact=True).tap()
            assert page.get_by_role("button", name="Reset zoom", exact=True).count() == 1
            assert editor.evaluate("e => document.activeElement === e")
            page.get_by_role("button", name="Done", exact=True).tap()
            assert editor.input_value() == ""
            assert page.get_by_role("button", name="Keyboard", exact=True).count() == 1
            assert page.get_by_role("button", name="Paste", exact=True).is_hidden()
        finally:
            browser.close()
