"""The locked-down browser (``signin_window.browser``), checked in a real Chromium on a display with no window manager.

As root, with Xvfb, xdotool and xwininfo installed (CI's e2e job)::

    uv run --group browser python -m signin_window.browser install-policy
    uv run --group browser python scripts/browser_check.py

Both ways a runner starts Chromium: a persistent context (kiosk mode reaches its windows) and ``browser.new_context()``
(``harden(context, browser)``). In each, against a stand-in site on localhost and with a route check like a runner's:

- the window fills the display, with no address bar;
- pages, a cross-origin frame and popups see no WebAuthn, so a site's passkey button falls back;
- typing an address after Ctrl+L goes nowhere, and Ctrl+T or Ctrl+N leaves no tab or window behind;
- popups work (the route check knows a popup's first page), and Alt+Left leads back from a link the check stopped.

Chromium's save-password offer is not in any page, so CI keeps screenshots of the display after a form is sent
($E2E_SHOTS/browser-*.png) for a person to look at. Exits 0 when everything held. Nothing leaves the machine.
"""

from __future__ import annotations

import asyncio
import http.server
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit

from playwright.async_api import async_playwright

from signin_window.browser import LAUNCH_ARGS, harden, policy_installed
from signin_window.hosts import top_level

W, H = 1280, 860
DISPLAY = ":97"
BASE = "http://localhost:{port}"
LOGIN = (
    "<!doctype html><title>login</title><body style='font:20px sans-serif'>"
    "<form action=/done.html method=post><input name=username autocomplete=username value=jane@example.com>"
    "<input type=password name=password autocomplete=current-password value='Example-pass-1'>"
    "<button id=go>Sign in</button></form>"
    "<p><button id=pop onclick=\"window.open('/done.html','pop','width=500,height=600')\">popup</button> "
    "<a id=away href='http://elsewhere.example.org/'>elsewhere</a> <button id=passkey>passkey</button></p>"
    "<iframe src='http://127.0.0.1:{port}/frame.html' width=400 height=60></iframe>"
    "<script>const d = document.documentElement.dataset; d.webauthn = typeof PublicKeyCredential;"
    "addEventListener('message', e => d.frame = e.data);"
    "document.getElementById('passkey').onclick = () => {"
    "if (!window.PublicKeyCredential) { d.passkey = 'none'; return; }"
    "navigator.credentials.get({publicKey: {challenge: new Uint8Array(16), rpId: location.hostname}})"
    ".then(() => d.passkey = 'ok', e => d.passkey = e.name) };</script>"
)
FRAME = "<!doctype html><body>frame<script>parent.postMessage(typeof PublicKeyCredential, '*')</script>"
DONE = (
    "<!doctype html><title>done</title><body style='font:20px sans-serif'><h1>Signed in (stand-in)</h1>"
    "<script>document.documentElement.dataset.webauthn = typeof PublicKeyCredential</script>"
)
# This check only: Chromium's local-network prompt would hold the loopback frame (a real site's frames are public).
CHECK_ARGS = ("--no-first-run", "--window-position=0,0", f"--window-size={W},{H}",
              "--disable-features=LocalNetworkAccessChecks")  # fmt: skip
SHOTS = Path(os.environ.get("E2E_SHOTS") or tempfile.mkdtemp(prefix="browser-shots-"))
FAILURES: list[str] = []


def serve() -> int:
    class Handler(http.server.BaseHTTPRequestHandler):
        def respond(self) -> None:
            port = self.server.server_address[1]
            pages = {"/login.html": LOGIN.replace("{port}", str(port)), "/done.html": DONE, "/frame.html": FRAME}
            body = pages.get(self.path.split("?")[0], "<h1>not here</h1>").encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:
            self.respond()

        def do_POST(self) -> None:
            self.rfile.read(int(self.headers.get("Content-Length") or 0))
            self.respond()

        def log_message(self, *args: object) -> None:
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server.server_address[1]


def x(*argv: str) -> str:
    return subprocess.run(argv, capture_output=True, text=True, env={**os.environ, "DISPLAY": DISPLAY}).stdout


def keys(*names: str) -> None:
    x("xdotool", "mousemove", str(W // 2), str(H // 2))  # no window manager: keys go to the window under the pointer
    for name in names:
        x("xdotool", "key", "--clearmodifiers", name)
        time.sleep(0.3)


def shot(name: str) -> None:
    path = SHOTS / f"browser-{name}.png"
    xwd = subprocess.run(["xwd", "-root", "-silent", "-display", DISPLAY], capture_output=True, check=False).stdout
    pnm = subprocess.run(["xwdtopnm"], input=xwd, capture_output=True, check=False).stdout
    path.write_bytes(subprocess.run(["pnmtopng"], input=pnm, capture_output=True, check=False).stdout)


def browser_windows() -> int:
    return sum(" - " in line and "+0+0" in line for line in x("xwininfo", "-root", "-children").splitlines())


def check(ok: bool, what: str) -> None:
    print(("ok   " if ok else "FAIL ") + what, flush=True)
    if not ok:
        FAILURES.append(what)


async def exercise(name: str, context, page, base: str) -> None:  # type: ignore[no-untyped-def]
    async def guard(route) -> None:  # type: ignore[no-untyped-def]
        if top_level(route.request) and urlsplit(route.request.url).hostname not in ("localhost", "127.0.0.1"):
            await route.abort()
        else:
            await route.continue_()

    await context.route("**/*", guard)
    login = f"{base}/login.html"
    await page.goto(login, wait_until="domcontentloaded")
    await asyncio.sleep(1.5)
    seen = await page.evaluate("[innerHeight, {...document.documentElement.dataset}]")
    check(seen[0] >= H - 1, f"{name}: the window fills the display, no address bar (inner height {seen[0]})")
    check(seen[1].get("webauthn") == "undefined", f"{name}: the page sees no WebAuthn")
    check(seen[1].get("frame") == "undefined", f"{name}: a cross-origin frame sees no WebAuthn")
    await page.click("#passkey")
    check(await page.evaluate("document.documentElement.dataset.passkey") == "none", f"{name}: no passkey dialog")
    shot(f"{name}-1-login")
    await page.click("#go")
    await page.wait_for_url("**/done.html")
    await asyncio.sleep(2.5)
    shot(f"{name}-2-form-sent")  # no "Save password?" here
    await page.goto(login, wait_until="domcontentloaded")
    keys("ctrl+l")
    x("xdotool", "type", "--delay", "30", base.removeprefix("http://") + "/done.html?typed")
    keys("Return")
    await asyncio.sleep(1.5)
    check(page.url == login, f"{name}: an address typed after Ctrl+L goes nowhere ({page.url})")
    keys("ctrl+t")
    await asyncio.sleep(2)
    keys("ctrl+n")
    await asyncio.sleep(2)
    open_pages = [p.url for p in context.pages if not p.is_closed()]
    check(open_pages == [login], f"{name}: Ctrl+T and Ctrl+N leave no tab behind ({open_pages})")
    check(browser_windows() == 1, f"{name}: ... and no window ({browser_windows()})")
    async with context.expect_page() as popup_info:
        await page.click("#pop")
    popup = await popup_info.value
    await popup.wait_for_load_state("domcontentloaded")
    check(popup.url.endswith("/done.html"), f"{name}: a popup opens ({popup.url})")
    check(await popup.evaluate("typeof PublicKeyCredential") == "undefined", f"{name}: a popup sees no WebAuthn")
    shot(f"{name}-3-popup")
    await popup.close()
    await page.click("#away")
    await asyncio.sleep(2)
    check(page.url != login and "elsewhere" not in page.url, f"{name}: the route check stopped a link ({page.url})")
    keys("alt+Left")
    await asyncio.sleep(2)
    check(page.url == login, f"{name}: Alt+Left leads back ({page.url})")


async def main() -> int:
    if not shutil.which("xdotool") or not shutil.which("Xvfb"):
        print("needs Xvfb, xdotool, xwininfo, xwd and netpbm", file=sys.stderr)
        return 2
    check(policy_installed(), "the managed policy is installed")
    SHOTS.mkdir(parents=True, exist_ok=True)
    base = BASE.format(port=serve())
    xvfb = subprocess.Popen(["Xvfb", DISPLAY, "-screen", "0", f"{W}x{H}x24", "-nolisten", "tcp"])
    env = {**os.environ, "DISPLAY": DISPLAY}
    try:
        time.sleep(1.5)
        async with async_playwright() as pw:
            with tempfile.TemporaryDirectory() as profile:
                context = await pw.chromium.launch_persistent_context(
                    profile, headless=False, no_viewport=True, env=env, args=[*CHECK_ARGS, *LAUNCH_ARGS]
                )
                try:
                    await harden(context)
                    page = context.pages[0] if context.pages else await context.new_page()
                    await exercise("persistent", context, page, base)
                finally:
                    await context.close()
            browser = await pw.chromium.launch(headless=False, env=env, args=[*CHECK_ARGS, *LAUNCH_ARGS])
            try:
                context = await browser.new_context(no_viewport=True)
                await harden(context, browser)
                await exercise("new-context", context, await context.new_page(), base)
            finally:
                await browser.close()
    finally:
        xvfb.terminate()
    print(f"screenshots in {SHOTS}")
    if FAILURES:
        print(f"{len(FAILURES)} check(s) failed", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
