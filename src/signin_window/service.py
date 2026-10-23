"""The login service: sign-in windows that a person drives themselves, through noVNC.

One window = one virtual display (Xvfb), one remote-desktop server on loopback (x11vnc), and whatever your *runner*
opens on that display: normally a browser on the site's own sign-in page. Nothing in this package clicks, types or
fills anything; the person does every step of the sign-in, the site's own checks included.

A runner is ``async def runner(window) -> dict | None`` (or a plain function, run in a thread). It opens the sign-in
page on ``window.env()``'s display, calls ``window.waiting(host)`` once the page is up (the only state with a live
view), and ends in one of two ways:

- **hand-over**: it returns the session (a JSON-able dict). The window is ``signed_in`` and the session waits, for
  ``RESULT_TTL``, to be taken once (``POST /logins/{id}/result``); then it is dropped.
- **kept**: it keeps the session itself (in a profile or snapshot this service owns) and calls
  ``window.finish(state)`` with a final state of its own, such as ``"connected"`` or ``"wrong_account"``.

States: ``starting`` -> ``waiting`` -> (``saving`` ->) ``signed_in`` (hand-over) or the runner's own final state; or
``failed``, ``expired`` (past its time), ``cancelled`` (closed early), ``busy`` (the shared lock stayed taken) or
``closed`` (its session was taken). Ended windows stay readable for ``ENDED_TTL`` so the caller sees how they ended.

The HTTP API (``build_app``) needs a bearer for everything but ``/health``, noVNC's files and the person's own view,
which needs the window's view token. Only the caller that started a window gets that token.
"""

from __future__ import annotations

import asyncio
import contextlib
import hmac
import inspect
import logging
import os
import re
import secrets
import shutil
import socket
import subprocess
import tempfile
import threading
import time
from collections.abc import Awaitable, Callable, Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, Response
from starlette.routing import BaseRoute, Mount, Route, WebSocketRoute
from starlette.staticfiles import StaticFiles
from starlette.types import ASGIApp, Receive, Scope, Send
from starlette.websockets import WebSocket, WebSocketDisconnect

log = logging.getLogger("signin_window")

#: Window sizes for the person's screen: the display is made this size, and so should the browser window be.
LAYOUTS: dict[str, tuple[int, int]] = {"desktop": (1280, 860), "phone": (430, 900)}
#: Open windows: they hold a slot and can still end either way. ``saving``: the person has signed in and the runner
#: is keeping the session (a kept session); the live view is closed and a cancel no longer interrupts it.
ACTIVE = ("starting", "waiting", "saving")
#: The one state with a live view: the sign-in page is up and nothing else may be on screen.
VIEWABLE = "waiting"
RESULT_TTL = 5 * 60  # a handed-over session waits this long to be taken, then it is dropped
ENDED_TTL = 5 * 60  # an ended window stays readable this long
STATE = re.compile(r"[a-z][a-z0-9_]{0,39}\Z")
MAX_INFO = 200  # characters per public info field


class Busy(Exception):
    """Every window slot is in use."""


@dataclass
class Window:
    """One sign-in window. Runners use ``env``, ``temp_profile``, ``waiting``, ``at``, ``report``, ``finish`` and
    ``cancelled``; ``params`` holds what the caller asked for when it started the window (validated by the
    service's ``start_params``)."""

    id: str
    layout: str
    slot: int
    created: float
    deadline: float
    params: dict[str, Any] = field(default_factory=dict)
    key: str | None = None
    state: str = "starting"
    host: str = ""
    error: str | None = None
    info: dict[str, str] = field(default_factory=dict)
    result: dict[str, Any] | None = field(default=None, repr=False)
    result_at: float | None = None
    ended_at: float | None = None
    procs: list[Any] = field(default_factory=list, repr=False)
    profiles: list[str] = field(default_factory=list, repr=False)
    task: asyncio.Task | None = field(default=None, repr=False)
    #: Set when the window must stop (closed, replaced or past its time): a runner in a thread polls it.
    cancelled: threading.Event = field(default_factory=threading.Event, repr=False)
    view_token: str = field(default_factory=lambda: secrets.token_urlsafe(24), repr=False)
    display_base: int = 90
    vnc_base: int = 5990
    #: The X display and loopback VNC port the service picked when it started the window (free ones, so a window
    #: never waits for the last one's to be released); before that, the slot's own.
    display_number: int | None = None
    vnc_number: int | None = None
    _outcome: tuple[str, str | None] | None = field(default=None, repr=False)

    @property
    def display(self) -> str:
        return f":{self.display_base + self.slot if self.display_number is None else self.display_number}"

    @property
    def vnc_port(self) -> int:
        return self.vnc_base + self.slot if self.vnc_number is None else self.vnc_number

    @property
    def size(self) -> tuple[int, int]:
        return LAYOUTS[self.layout]

    def env(self, base: Mapping[str, str] | None = None) -> dict[str, str]:
        """An environment for a process on this window's display (``base`` defaults to this process's)."""
        return {**(os.environ if base is None else base), "DISPLAY": self.display}

    def temp_profile(self, prefix: str = "signin-") -> str:
        """A new private directory for a throwaway browser profile, removed when the window ends."""
        path = tempfile.mkdtemp(prefix=prefix)
        self.profiles.append(path)
        return path

    # -- what a runner reports ----------------------------------------------------------------------------------

    def waiting(self, host: str = "") -> None:
        """The sign-in page is up: the live view opens."""
        if host:
            self.at(host)
        if self.state == "starting":
            self.state = "waiting"

    def saving(self) -> None:
        """The person has signed in; the runner is now keeping the session. The live view closes, and closing the
        window no longer interrupts the runner (the sign-in is done)."""
        if self.state in ("starting", "waiting"):
            self.state = "saving"

    def at(self, host: str) -> None:
        """The host the window shows now (the page tells the person where they are)."""
        self.host = str(host)[:100]

    def report(self, **fields: object) -> None:
        """Public fields for the caller (``GET /logins/{id}``), such as the account a kept session belongs to."""
        for name, value in fields.items():
            if STATE.match(name) and name not in ("id", "state", "host", "error", "layout"):
                self.info[name] = str(value)[:MAX_INFO]

    def finish(self, state: str, error: str | None = None) -> None:
        """End with a final state of the runner's own (a kept session: ``"connected"``, ``"wrong_account"``, ...)."""
        if not STATE.match(state) or state in (*ACTIVE, "signed_in"):
            raise ValueError(f"not a final state: {state!r}")
        self._outcome = (state, error)

    def public(self) -> dict[str, Any]:
        return {**self.info, "id": self.id, "state": self.state, "host": self.host, "error": self.error,
                "layout": self.layout}  # fmt: skip

    def view_ok(self, token: str) -> bool:
        return secrets.compare_digest(token or "", self.view_token)


Runner = Callable[[Window], Awaitable[dict[str, Any] | None]] | Callable[[Window], dict[str, Any] | None]


class Windows:
    """The service's windows: slots, displays, time limits, and the one-time hand-over of a session.

    ``lock``, if given, is held while a runner runs (a keeper that uses the same browser profile takes it too); a
    window that cannot get it within ``lock_wait`` seconds ends ``busy``. Window ``n`` (from 0) uses X display
    ``display_base + n`` and the loopback VNC port ``vnc_base + n``.
    """

    def __init__(
        self,
        runner: Runner,
        *,
        slots: int = 1,
        minutes: int = 15,
        xvfb: str = "Xvfb",
        x11vnc: str = "x11vnc",
        lock: threading.Lock | None = None,
        lock_wait: float = 90,
        display_base: int = 90,
        vnc_base: int = 5990,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if slots < 1 or slots > 9:
            raise ValueError("slots must be 1 to 9")
        self.runner, self.slots, self.limit = runner, slots, minutes * 60
        self.xvfb, self.x11vnc = xvfb, x11vnc
        self.lock, self.lock_wait = lock, lock_wait
        self.display_base, self.vnc_base = display_base, vnc_base
        self._clock = clock
        self._windows: dict[str, Window] = {}
        self._guard = threading.Lock()

    async def start(self, layout: str = "desktop", params: Mapping[str, Any] | None = None) -> Window:
        """Open a window; ``params["key"]``, if given, names what it signs in (an account, a site): a newer window
        for the same key cancels the older one."""
        if layout not in LAYOUTS:
            raise ValueError("layout")
        params = dict(params or {})
        key = str(params["key"]) if params.get("key") is not None else None
        with self._guard:
            self._reap()
            if key is not None:
                for other in self._windows.values():
                    if other.key == key and other.state in ("starting", "waiting"):  # a saving one finishes
                        self._cancel(other)
            used = {w.slot for w in self._windows.values() if w.state in ACTIVE}
            free = [slot for slot in range(self.slots) if slot not in used]
            if not free:
                raise Busy()
            now = self._clock()
            window = Window(secrets.token_urlsafe(18), layout, free[0], now, now + self.limit, params, key,
                            display_base=self.display_base, vnc_base=self.vnc_base)  # fmt: skip
            self._windows[window.id] = window
        try:
            await asyncio.to_thread(self.start_display, window)
        except Exception:
            self._end(window, "failed", "display")
            raise
        window.task = asyncio.create_task(self._run(window))
        return window

    def get(self, window_id: str) -> Window | None:
        with self._guard:
            self._reap()
            return self._windows.get(window_id)

    def take(self, window_id: str) -> dict[str, Any] | None:
        """The handed-over session, once; the window is ``closed`` after that."""
        with self._guard:
            self._reap()
            window = self._windows.get(window_id)
            if window is None or window.state != "signed_in" or window.result is None:
                return None
            result, window.result = window.result, None
            window.state, window.ended_at = "closed", self._clock()
            return result

    async def close(self, window_id: str) -> None:
        """Cancel a window that is still open, or drop a session nobody took."""
        with self._guard:
            window = self._windows.get(window_id)
            if window is None:
                return
            if window.state == "signed_in":
                window.result = None
                window.state, window.ended_at = "closed", self._clock()
                return
            if window.state not in ("starting", "waiting"):  # ended, or saving a finished sign-in
                return
            self._cancel(window)
            task = window.task
        if task is not None and task is not asyncio.current_task():
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await asyncio.wait_for(asyncio.shield(task), timeout=10)

    async def close_all(self) -> None:
        for window_id in list(self._windows):
            await self.close(window_id)

    async def close_key(self, key: str) -> None:
        """Close every window of ``key`` (an account being removed, say)."""
        for window in [w for w in list(self._windows.values()) if w.key == key]:
            await self.close(window.id)

    def _cancel(self, window: Window) -> None:
        window.cancelled.set()
        if window.task is not None and not window.task.done():
            window.task.cancel()

    def _reap(self) -> None:
        """Windows past their time are stopped; untaken sessions and ended windows are dropped (hold ``_guard``)."""
        now = self._clock()
        for window in list(self._windows.values()):
            if window.state in ("starting", "waiting") and now > window.deadline:
                self._cancel(window)
            elif window.state == "signed_in" and window.result_at is not None and now - window.result_at > RESULT_TTL:
                window.result = None
                window.state, window.ended_at = "expired", now
            elif window.state != "signed_in" and window.ended_at is not None and now - window.ended_at > ENDED_TTL:
                self._windows.pop(window.id, None)

    # -- the runner ---------------------------------------------------------------------------------------------

    async def _run(self, window: Window) -> None:
        locked = False
        try:
            if self.lock is not None:
                locked = await asyncio.to_thread(self.lock.acquire, True, self.lock_wait)
                if not locked:
                    self._end(window, "busy")
                    return
            if window.cancelled.is_set():
                raise asyncio.CancelledError
            if inspect.iscoroutinefunction(self.runner):
                result = await self.runner(window)
            else:
                result = await self._in_thread(window)
            if window._outcome is not None:
                self._end(window, *window._outcome)
            elif isinstance(result, dict) and not window.cancelled.is_set():
                self._end(window, "signed_in", result=result)
            else:
                self._end(window, "failed", window.error or "no_session")
        except asyncio.CancelledError:
            if window._outcome is not None:  # it finished all the same (a kept session being saved)
                self._end(window, *window._outcome)
            else:
                self._end(window, "expired" if self._clock() > window.deadline else "cancelled")
        except Exception as exc:
            log.warning("window %s failed: %s", window.id[:6], type(exc).__name__)
            self._end(window, "failed", window.error or type(exc).__name__)
        finally:
            if locked:
                self.lock.release()

    async def _in_thread(self, window: Window) -> dict[str, Any] | None:
        """A plain-function runner, in a thread. A thread cannot be cancelled: on cancel, ``window.cancelled`` tells
        the runner to stop, and the window waits for it, so the lock is never released under a running browser."""
        worker = asyncio.ensure_future(asyncio.to_thread(self.runner, window))
        try:
            return await asyncio.shield(worker)
        except asyncio.CancelledError:
            window.cancelled.set()
            await asyncio.wait({worker})
            raise

    def _end(self, window: Window, state: str, error: str | None = None, result: dict[str, Any] | None = None) -> None:
        if window.ended_at is not None:
            return
        now = self._clock()
        window.state, window.error, window.ended_at = state, error or window.error, now
        if result is not None:
            window.result, window.result_at = result, now
        self.stop_display(window)
        for path in window.profiles:
            shutil.rmtree(path, ignore_errors=True)
        window.profiles.clear()
        log.info("window %s ended: %s%s", window.id[:6], state, f" ({window.error})" if window.error else "")

    # -- the display and its remote-desktop server --------------------------------------------------------------

    #: Where X servers keep their lock files and sockets.
    x_tmp = Path("/tmp")  # noqa: S108 (fixed by X itself)
    #: How long a display or its VNC server may take to come up.
    ready_wait = 10.0

    def start_display(self, window: Window) -> None:
        """Start the window's display and its VNC server on a display number and port that are free now (another
        window's, or one a just-ended window has not released yet, are skipped), and wait until both are ready."""
        with self._guard:
            others = [w for w in self._windows.values() if w is not window and w.ended_at is None]
            window.display_number = self._free_display({w.display_number for w in others})
            window.vnc_number = self._free_port({w.vnc_number for w in others})
        width, height = window.size
        window.procs.append(
            subprocess.Popen(
                [self.xvfb, window.display, "-screen", "0", f"{width}x{height}x24", "-nolisten", "tcp"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        )
        self._wait(lambda: (self.x_tmp / ".X11-unix" / f"X{window.display_number}").exists(), window, "Xvfb")
        # Loopback only: the service's WebSocket bridge, behind the view token, is the one way in.
        window.procs.append(
            subprocess.Popen(
                [self.x11vnc, "-display", window.display, "-localhost", "-rfbport", str(window.vnc_port), "-nopw",
                 "-forever", "-shared", "-quiet", "-noxdamage"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        )  # fmt: skip
        self._wait(lambda: _listening(window.vnc_port), window, "x11vnc")

    def _wait(self, ready: Callable[[], bool], window: Window, what: str) -> None:
        deadline = time.monotonic() + self.ready_wait
        while not ready():
            if any(proc.poll() is not None for proc in window.procs) or time.monotonic() > deadline:
                raise RuntimeError(f"{what} did not start")
            time.sleep(0.05)

    def _free_display(self, taken: set[int | None]) -> int:
        for number in range(self.display_base, self.display_base + 100):
            in_use = (self.x_tmp / f".X{number}-lock").exists() or (self.x_tmp / ".X11-unix" / f"X{number}").exists()
            if number not in taken and not in_use:
                return number
        raise Busy()

    def _free_port(self, taken: set[int | None]) -> int:
        for port in range(self.vnc_base, self.vnc_base + 100):
            if port not in taken and _bindable(port):
                return port
        raise Busy()

    def stop_display(self, window: Window) -> None:
        for proc in reversed(window.procs):
            with contextlib.suppress(ProcessLookupError, PermissionError):
                proc.terminate()
        for proc in window.procs:
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                with contextlib.suppress(ProcessLookupError, PermissionError):
                    proc.kill()
                with contextlib.suppress(subprocess.TimeoutExpired):
                    proc.wait(timeout=2)
        window.procs.clear()


def _bindable(port: int) -> bool:
    """Whether a server could listen on this loopback port now (x11vnc does not reuse a port still in use)."""
    with socket.socket() as sock:
        try:
            sock.bind(("127.0.0.1", port))
        except OSError:
            return False
    return True


def _listening(port: int) -> bool:
    with socket.socket() as sock:
        sock.settimeout(0.2)
        return sock.connect_ex(("127.0.0.1", port)) == 0


# -- the HTTP API ---------------------------------------------------------------------------------------------------

VIEW_PAGE = """<!doctype html><meta name=viewport content="width=device-width,initial-scale=1">
<meta name=referrer content=no-referrer>
<title>{{TITLE}}</title>
<style>
 html,body{margin:0;height:100%;font:15px system-ui;background:#f4f5f4}
 header{padding:.6em 1em;background:#fff;border-bottom:1px solid #ddd}
 header b{font-size:1.05em} .url{color:#2a7a2a;font-size:.85em;margin-top:.2em}
 #screen{position:absolute;top:4.2em;bottom:2.4em;left:0;right:0;background:#fff}
 footer{position:absolute;bottom:0;left:0;right:0;padding:.5em 1em;font-size:.8em;color:#555;background:#fff;
  border-top:1px solid #ddd}
 #done{display:none;padding:3em 1em;text-align:center;font-size:1.2em}
</style>
<header><b>{{TITLE}}</b><div class=url id=url></div></header>
<div id=screen></div><div id=done></div>
<footer id=status>Sign in as you usually do. This page finishes by itself.</footer>
<script type=module>
import RFB from '/novnc/core/rfb.js';
const id = location.pathname.split('/')[2], t = new URLSearchParams(location.search).get('t');
history.replaceState(null, '', location.pathname);  // keep the token out of the address bar
const ws = (location.protocol === 'https:' ? 'wss' : 'ws') + '://' + location.host;
let rfb = null;
const status = document.getElementById('status');
async function poll() {
  let s;
  try { s = await (await fetch(`/view/${id}/state?t=${encodeURIComponent(t)}`)).json(); } catch (e) { s = {}; }
  if (s.host) document.getElementById('url').textContent = s.host;
  if (s.state === 'waiting' && !rfb) {
    rfb = new RFB(document.getElementById('screen'), `${ws}/logins/${id}/vnc?t=${encodeURIComponent(t)}`);
    rfb.scaleViewport = true; rfb.resizeSession = false; rfb.focusOnClick = true;
  }
  if (s.state && !['starting', 'waiting'].includes(s.state)) {
    if (rfb) rfb.disconnect();
    document.getElementById('screen').remove();
    const d = document.getElementById('done'); d.style.display = 'block';
    d.textContent = ['signed_in', 'closed', 'connected'].includes(s.state)
      ? 'Signed in. You can close this page.' : `That did not work (${s.state}).`;
    status.textContent = ''; return;
  }
  setTimeout(poll, 1000);
}
poll();
</script>"""


class BearerOnly:
    """Every route but /health, /novnc and the person's view (its own token) needs the bearer, checked before any
    WebSocket handshake too."""

    def __init__(self, app: ASGIApp, token: str) -> None:
        self.app, self.expected = app, f"Bearer {token}".encode()

    @staticmethod
    def _open(scope: Scope) -> bool:
        path = scope.get("path") or ""
        if scope["type"] == "websocket":
            return path.startswith("/logins/") and path.endswith("/vnc")  # the view token is checked there
        return path == "/health" or path.startswith(("/novnc/", "/view/"))

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] in ("http", "websocket") and not self._open(scope):
            given = dict(scope.get("headers") or []).get(b"authorization", b"")
            if not hmac.compare_digest(given, self.expected):
                if scope["type"] == "websocket":
                    await send({"type": "websocket.close", "code": 4401})
                else:
                    await Response(status_code=401)(scope, receive, send)
                return
        await self.app(scope, receive, send)


def build_app(
    windows: Windows,
    *,
    token: str,
    novnc_dir: Path | str,
    start_params: Callable[[dict[str, Any]], Mapping[str, Any]] | None = None,
    title: str = "Sign in",
    routes: Iterable[BaseRoute] = (),
) -> Starlette:
    """The login service's API::

        POST   /logins               {"layout": "phone"|"desktop", ...} -> 201 {id, state, view_token, ...} | 503
        GET    /logins/{id}          -> {id, state, host, error, layout, ...the runner's report}
        POST   /logins/{id}/result   -> the handed-over session, once | 409 not (or no longer) signed in
        DELETE /logins/{id}          -> 204: cancel the window, or drop an untaken session
        WS     /logins/{id}/vnc?t=   -> the window's remote-desktop stream (RFB) for noVNC, while ``waiting``
        GET    /view/{id}?t=         -> a plain page showing the window (for a person on the service's own network)
        GET    /novnc/...            -> noVNC's own files (``novnc_dir``)
        GET    /health

    ``start_params(body)`` turns the start request into the window's ``params`` (raise ``ValueError`` to refuse it
    with 400); without it, a start takes no parameters. ``routes`` adds your own (behind the bearer).
    """
    if len(token) < 32:
        raise ValueError("the bearer token must have at least 32 characters")
    novnc_dir = Path(novnc_dir)

    async def health(_: Request) -> JSONResponse:
        return JSONResponse({"status": "healthy"})

    async def start(request: Request) -> JSONResponse:
        try:
            body = await request.json()
        except ValueError:
            body = {}
        body = body if isinstance(body, dict) else {}
        layout = body.get("layout") if body.get("layout") in LAYOUTS else "desktop"
        try:
            params = dict(start_params(body)) if start_params else {}
        except ValueError:
            return JSONResponse({"error": "bad_request"}, status_code=400)
        try:
            window = await windows.start(layout, params)
        except Busy:
            return JSONResponse({"error": "busy"}, status_code=503)
        return JSONResponse({**window.public(), "view_token": window.view_token}, status_code=201)

    async def state(request: Request) -> JSONResponse:
        window = windows.get(request.path_params["id"])
        if window is None:
            return JSONResponse({"error": "unknown"}, status_code=404)
        return JSONResponse(window.public())

    async def result(request: Request) -> JSONResponse:
        window_id = request.path_params["id"]
        if windows.get(window_id) is None:
            return JSONResponse({"error": "unknown"}, status_code=404)
        session = windows.take(window_id)
        if session is None:
            return JSONResponse({"error": "not_signed_in"}, status_code=409)
        return JSONResponse(session, headers={"Cache-Control": "no-store"})

    async def close(request: Request) -> Response:
        await windows.close(request.path_params["id"])
        return Response(status_code=204)

    def viewable(window_id: str, view_token: str) -> Window | None:
        window = windows.get(window_id)
        return window if window is not None and window.view_ok(view_token) else None

    async def view(request: Request) -> Response:
        if viewable(request.path_params["id"], request.query_params.get("t", "")) is None:
            return Response(status_code=404)
        page = VIEW_PAGE.replace("{{TITLE}}", _escape(title))
        return HTMLResponse(page, headers={"Cache-Control": "no-store", "X-Frame-Options": "DENY"})

    async def view_state(request: Request) -> JSONResponse:
        window = viewable(request.path_params["id"], request.query_params.get("t", ""))
        if window is None:
            return JSONResponse({"state": "unknown"})
        return JSONResponse({"state": window.state, "host": window.host})

    async def vnc(ws: WebSocket) -> None:
        window = viewable(ws.path_params["id"], ws.query_params.get("t", ""))
        if window is None or window.state != VIEWABLE:
            await ws.close(code=4404)
            return
        await ws.accept(subprotocol="binary" if "binary" in ws.scope.get("subprotocols", []) else None)
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", window.vnc_port)
        except OSError:
            await ws.close(code=1011)
            return
        await _pipe(ws, reader, writer, lambda: window.state == VIEWABLE)

    all_routes: list[BaseRoute] = [
        Route("/health", health),
        Route("/logins", start, methods=["POST"]),
        Route("/logins/{id}", state, methods=["GET"]),
        Route("/logins/{id}", close, methods=["DELETE"]),
        Route("/logins/{id}/result", result, methods=["POST"]),
        Route("/view/{id}", view, methods=["GET"]),
        Route("/view/{id}/state", view_state, methods=["GET"]),
        WebSocketRoute("/logins/{id}/vnc", vnc),
        *routes,
    ]
    if novnc_dir.is_dir():
        all_routes.append(Mount("/novnc", app=StaticFiles(directory=novnc_dir)))

    @contextlib.asynccontextmanager
    async def lifespan(_: Starlette):  # type: ignore[no-untyped-def]
        yield
        await windows.close_all()  # on shutdown: runners stop, displays and profiles go

    return Starlette(routes=all_routes, middleware=[Middleware(BearerOnly, token=token)], lifespan=lifespan)


async def _pipe(ws: WebSocket, reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                still_open: Callable[[], bool]) -> None:  # fmt: skip
    """Relay bytes both ways until either side closes or the window stops being viewable."""

    async def upstream() -> None:
        try:
            while True:
                message = await ws.receive()
                if message["type"] == "websocket.disconnect":
                    return
                writer.write(message.get("bytes") or (message.get("text") or "").encode())
                await writer.drain()
        except (WebSocketDisconnect, ConnectionError):
            return

    async def downstream() -> None:
        try:
            while data := await reader.read(65536):
                await ws.send_bytes(data)
        except (WebSocketDisconnect, ConnectionError, RuntimeError):
            return

    async def watch() -> None:
        while still_open():
            await asyncio.sleep(1)

    tasks = [asyncio.create_task(upstream()), asyncio.create_task(downstream()), asyncio.create_task(watch())]
    await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    for task in tasks:
        task.cancel()
    writer.close()
    with contextlib.suppress(Exception):
        await ws.close()


def _escape(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
