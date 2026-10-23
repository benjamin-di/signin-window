"""End to end, with real browsers and no real site: a sign-in link, its live view, paste, a hand-over, and closing.

Runs a login service (``signin_window.service``) whose runner opens a stand-in sign-in page (one text field) in a
headed Chromium on the window's virtual display, and a server with the relay (``signin_window.relay``) mounted under
``/app/connect`` as behind a path-stripping reverse proxy. Then, as the person, in a headless Chromium:

1. opens a link, continues, and waits for the live view (noVNC through the relay and the service);
2. types a key, then puts text on the clipboard and presses Ctrl+V: the text must arrive in the remote field,
   typed (clipboard *reading* is not granted to the page, so it can only have come from the browser's paste event);
3. the stand-in "signs in" once the field holds the text: the window hands its session over, the relay's hook
   stores it, and the page says so;
4. opens a second link and closes the page: that must close its window.

Needs Xvfb, x11vnc, noVNC's files and Playwright's Chromium::

    NOVNC_DIR=/opt/novnc uv run --group browser python scripts/e2e.py

Exits 0 when everything worked. Nothing leaves the machine.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import socket
import sys
import tempfile
from pathlib import Path

import uvicorn
from playwright.async_api import async_playwright
from starlette.applications import Starlette
from starlette.routing import Mount

from signin_window.client import LoginClient
from signin_window.page import PageText
from signin_window.relay import Relay
from signin_window.service import Window, Windows, build_app

# ASCII only: the virtual display's keyboard has no keys for other characters (x11vnc drops their keysyms).
TEXT = "Hello, Example 123 @#%&*()[]{}<>?/|~ pass:Word_-+=."
FIELD_PAGE = (
    "<!doctype html><title>stand-in</title>"
    "<input id=f autofocus style='position:fixed;inset:0;width:100%;height:100%;font-size:24px'>"
    "<script>const d = document.documentElement.dataset; d.mouse = d.keys = 0;"
    "addEventListener('mousedown', () => d.mouse++, true); addEventListener('keydown', () => d.keys++, true);"
    "</script>"
)
TOKEN = "e2e-login-token-0123456789abcdef0123"


def logged(binary: str) -> str:
    """With $E2E_SHOTS set, a wrapper that keeps the binary's output there (the service discards it)."""
    shots = os.environ.get("E2E_SHOTS")
    if not shots:
        return binary
    Path(shots).mkdir(parents=True, exist_ok=True)
    name = Path(binary).name
    wrapper = Path(tempfile.mkdtemp(prefix="e2e-bin-")) / name
    wrapper.write_text(f'#!/bin/sh\nexec {binary} "$@" >>"{shots}/{name}.log" 2>&1\n')
    wrapper.chmod(0o755)
    return str(wrapper)


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


async def serve(app, port: int) -> uvicorn.Server:  # type: ignore[no-untyped-def]
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    asyncio.get_running_loop().create_task(server.serve())
    for _ in range(100):
        if server.started:
            return server
        await asyncio.sleep(0.05)
    raise SystemExit("a server did not start")


SHOTS: dict = {}  # pages to photograph when a step fails (into $E2E_SHOTS, for CI's artifacts)


async def wait_for(check, what: str, seconds: float = 30) -> None:  # type: ignore[no-untyped-def]
    for _ in range(int(seconds * 10)):
        if await check():
            return
        await asyncio.sleep(0.1)
    if "remote" in SHOTS:  # what reached the remote page: tells input that never arrived from input it ignored
        with contextlib.suppress(Exception):
            seen = await SHOTS["remote"].evaluate("({...document.documentElement.dataset})")
            print(f"the remote page saw: {seen}", file=sys.stderr)
    shots = Path(os.environ.get("E2E_SHOTS") or tempfile.mkdtemp(prefix="e2e-shots-"))
    shots.mkdir(parents=True, exist_ok=True)
    for name, page in list(SHOTS.items()):
        with contextlib.suppress(Exception):
            await page.screenshot(path=str(shots / f"{name}.png"))
    raise SystemExit(f"FAIL: {what} (screenshots in {shots})")


async def main(windows_box: list) -> int:
    login_port, app_port = free_port(), free_port()
    remote: dict = {}
    stored: dict = {}

    async with async_playwright() as pw:

        async def stand_in(window: Window) -> dict | None:
            """Instead of a real site: one text field, in a headed Chromium on the window's display. It counts as
            signed in once the field holds the pasted text."""
            # The window fills the display: with no window manager, keys go to the window under the pointer.
            width, height = window.size
            browser = await pw.chromium.launch(
                headless=False, env=window.env(), args=["--window-position=0,0", f"--window-size={width},{height}"]
            )
            try:
                page = await browser.new_page(no_viewport=True)
                await page.set_content(FIELD_PAGE)
                await page.focus("#f")
                remote["page"] = SHOTS["remote"] = page
                window.waiting("accounts.example.com")
                while not window.cancelled.is_set():
                    if (await page.input_value("#f")).endswith(TEXT):
                        return {"cookies": [{"name": "session", "value": "e2e"}]}
                    await asyncio.sleep(0.2)
                return None
            finally:
                remote.pop("page", None)
                await browser.close()

        windows = Windows(
            stand_in,
            slots=1,
            minutes=5,
            xvfb=logged(os.environ.get("XVFB") or "Xvfb"),
            x11vnc=logged(os.environ.get("X11VNC") or "x11vnc"),
        )
        windows_box.append(windows)
        novnc = Path(os.environ.get("NOVNC_DIR") or "/opt/novnc")
        if not (novnc / "vnc.html").is_file():
            raise SystemExit(f"no noVNC in {novnc} (set NOVNC_DIR)")
        await serve(build_app(windows, token=TOKEN, novnc_dir=novnc), login_port)

        def store(link, session):  # type: ignore[no-untyped-def]
            stored[link.key] = session
            link.show(name="Jane Example")
            return "connected"

        base = f"http://127.0.0.1:{app_port}/app/connect"
        relay = Relay(
            LoginClient(f"http://127.0.0.1:{login_port}", TOKEN),
            base,
            text=PageText(service="Example").with_outcomes(connected="<h1>Connected as {name}</h1>"),
            on_signed_in=store,
        )
        await serve(Starlette(routes=[Mount("/app", routes=relay.routes("/connect"))]), app_port)

        link = relay.create("jane")
        viewer = await pw.chromium.launch(headless=True)
        context = await viewer.new_context(viewport={"width": 1280, "height": 800})
        await context.grant_permissions(["clipboard-write"], origin=f"http://127.0.0.1:{app_port}")
        page = SHOTS["viewer"] = await context.new_page()
        await page.goto(link.url)
        await page.click("#go")  # the page names the account and waits for the person to continue
        frame_element = await page.wait_for_selector("iframe", timeout=60_000)
        frame = await frame_element.content_frame()
        assert frame is not None
        await frame.wait_for_function("document.documentElement.classList.contains('noVNC_connected')", timeout=60_000)
        print("live view connected through the link")

        canvas = await frame.wait_for_selector("#noVNC_container canvas")
        await canvas.click()  # focuses the viewer, and the remote field under the pointer
        await remote["page"].focus("#f")
        await page.keyboard.press("y")  # plain typing reaches the field before the paste is tried
        await wait_for(lambda: _value(remote, "y"), "a typed key did not reach the remote page")
        await page.keyboard.press("Backspace")
        await page.evaluate("text => navigator.clipboard.writeText(text)", TEXT)
        await page.keyboard.press("Control+V")
        print("pasted; waiting for the stand-in to sign in")

        await wait_for(
            lambda: page.locator("#done h1").is_visible(), "the page never said the sign-in ended", seconds=60
        )
        heading = await page.locator("#done h1").inner_text()
        if heading != "Connected as Jane Example" or stored != {
            "jane": {"cookies": [{"name": "session", "value": "e2e"}]}
        }:
            print(f"FAIL: the page says {heading!r}; stored {stored!r}", file=sys.stderr)
            return 1
        print("Ctrl+V typed the clipboard into the remote page; the session was handed over and stored")

        second = relay.create("john")
        page = await context.new_page()
        await page.goto(second.url)
        await page.click("#go")
        await page.wait_for_selector("iframe", timeout=60_000)
        await page.close(run_before_unload=True)  # pagehide sends the cancel
        await wait_for(lambda: _no_open_window(windows), "closing the page did not close the window", seconds=30)
        print("closing the page closed the sign-in window")
        await viewer.close()
    print("e2e: ok")
    return 0


async def _value(remote: dict, expected: str) -> bool:
    return "page" in remote and await remote["page"].input_value("#f") == expected


async def _no_open_window(windows: Windows) -> bool:
    return not any(w.state in ("starting", "waiting") for w in list(windows._windows.values()))


async def run() -> int:
    box: list = []
    try:
        return await main(box)
    finally:
        for windows in box:
            with contextlib.suppress(Exception):
                await windows.close_all()  # never leave a display or browser behind


if __name__ == "__main__":
    sys.exit(asyncio.run(run()))
