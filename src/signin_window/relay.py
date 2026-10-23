"""Sign-in links, served by your MCP server: a person signs in to their own account from any browser.

``Relay.create(key)`` makes a link ``<public_url>/<id>``: an unguessable id (192 random bits) that works for
``link_ttl`` and one successful sign-in. Its page (``signin_window.page``) shows the site's own sign-in page, running
in a window of your login service (``signin_window.service``) and viewed through noVNC; this relay carries the
viewer's files and its live view, so the login service never faces the internet. Nothing here is behind your
server's bearer: the id is the credential. A newer link for the same key replaces the older one.

When the window ends, one of your hooks says how it went, and the link takes that state:

- ``on_signed_in(link, session) -> state``: the window handed a session over (it is taken from the service once,
  here). Check it and store it for the link's key, then return ``"connected"`` (or a state of your own such as
  ``"wrong_account"``; anything else, or an exception, is ``"failed"``). Without this hook, a hand-over fails.
- ``on_ended(link, window_state) -> state``: the window ended without a hand-over; by default its state is kept
  when the page has a message for it (a login service that keeps sessions itself reports ``"connected"`` and the
  like), else ``"failed"``.

``before_start(link) -> state | None``, if given, runs before each window opens: return None to go on, or a state of
your own (say ``"invite_required"``) to refuse; it may also add to ``link.params``.

Hooks run one at a time, in a worker thread. ``link.show(name=...)`` adds public fields to the link's state (the
page can show them). The link never shows, returns or reads a session.

Routes, under the prefix you mount them at::

    GET  /{id}               the page
    POST /{id}/start         open a window (the layout follows the person's screen)
    GET  /{id}/state         progress; runs your hook once the window ends
    POST /{id}/cancel        close the window (the page sends it when it is closed)
    GET  /{id}/novnc/...     the viewer's files (noVNC from the login service, plus the paste add-on)
    WS   /{id}/vnc           the live view of the window
"""

from __future__ import annotations

import collections
import logging
import re
import secrets
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from importlib import resources
from typing import Any, Protocol

import anyio.to_thread
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, Response
from starlette.routing import BaseRoute, Route, WebSocketRoute
from starlette.websockets import WebSocket

from .client import LoginBusy, LoginUnavailable
from .page import PageText, render

log = logging.getLogger("signin_window")

LINK_ID = re.compile(r"[A-Za-z0-9_-]{32,64}\Z")
FIELD = re.compile(r"[a-z_][a-z0-9_]{0,39}\Z")
ACTIVE = ("starting", "waiting", "saving")
FINAL = ("connected",)
MISS_WINDOW, MISSES_PER_ADDRESS, MISSES_TOTAL = 10 * 60, 20, 200  # requests for ids that do not exist
HEADERS = {
    "Cache-Control": "no-store",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
}
PAGE_HEADERS = {
    **HEADERS,
    "X-Frame-Options": "DENY",
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; connect-src 'self'; frame-src 'self'; frame-ancestors 'none'; base-uri 'none'; "
        "form-action 'none'"
    ),
}
PASTE_JS = resources.files("signin_window").joinpath("static/paste.js").read_bytes()
PASTE_TAG = b'<script type="module" src="paste.js"></script>'


class Backend(Protocol):
    """The login service as the relay uses it (``signin_window.client.LoginClient``, or your own)."""

    def start(self, layout: str = "desktop", **params: Any) -> dict[str, Any]: ...

    def state(self, window_id: str) -> dict[str, Any]: ...

    def result(self, window_id: str) -> dict[str, Any] | None: ...

    def close(self, window_id: str) -> None: ...

    def static(self, path: str) -> tuple[int, bytes, str]: ...

    async def bridge(self, window_id: str, view_token: str, ws: Any) -> None: ...


class LinkLimited(Exception):
    """Too many links for this key this hour."""


@dataclass
class Link:
    id: str
    key: str
    created: float
    expires: float
    url: str
    params: dict[str, Any] = field(default_factory=dict)
    label: str = ""
    state: str = "ready"
    window_id: str | None = None
    view_token: str | None = field(default=None, repr=False)
    host: str = ""
    shown: dict[str, str] = field(default_factory=dict)
    starts: int = 0
    closed: bool = False  # replaced by a newer link or expired: it opens nothing any more
    lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def show(self, **fields: object) -> None:
        """Public fields of the link's state, for its page (never a secret: the page is the id's holder's)."""
        for name, value in fields.items():
            if FIELD.match(name) and name not in ("state", "host"):
                self.shown[name] = str(value)[:100]

    def public(self) -> dict[str, Any]:
        return {**self.shown, "state": self.state, "host": self.host}

    @property
    def expires_at(self) -> str:
        return datetime.fromtimestamp(self.expires, UTC).isoformat(timespec="seconds")


class Misses:
    """Requests for link ids that do not exist, per address and in total: guessing is slowed long before it could
    matter."""

    def __init__(self) -> None:
        self.by_address: dict[str, collections.deque] = {}
        self.total: collections.deque = collections.deque()

    def allowed(self, address: str, now: float) -> bool:
        if len(self.by_address) > 10_000:
            self.by_address.clear()
        for queue in (self.total, self.by_address.setdefault(address, collections.deque())):
            while queue and now - queue[0] > MISS_WINDOW:
                queue.popleft()
        return len(self.total) < MISSES_TOTAL and len(self.by_address[address]) < MISSES_PER_ADDRESS

    def record(self, address: str, now: float) -> None:
        self.total.append(now)
        self.by_address.setdefault(address, collections.deque()).append(now)


def forwarded_for(request: Request | WebSocket) -> str:
    """The client's address as the reverse proxy in front reports it (first X-Forwarded-For hop). Without a proxy
    that sets it, every client shares one bucket of misses."""
    return (request.headers.get("x-forwarded-for") or "unknown").split(",")[0].strip()[:64]


class Relay:
    def __init__(
        self,
        backend: Backend,
        public_url: str,
        *,
        text: PageText | None = None,
        on_signed_in: Callable[[Link, dict[str, Any]], str] | None = None,
        on_ended: Callable[[Link, dict[str, Any]], str] | None = None,
        before_start: Callable[[Link], str | None] | None = None,
        link_ttl: int = 20 * 60,
        max_links: int = 50,
        links_per_hour: int = 6,
        max_starts: int = 4,
        client_address: Callable[[Request | WebSocket], str] = forwarded_for,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if not re.match(r"https?://[^/?#]+(/[^?#]*)?\Z", public_url):
            raise ValueError("public_url must be an http(s) URL without a query")
        self.backend, self.public_url = backend, public_url.rstrip("/")
        self.text = text or PageText()
        self._on_signed_in, self._on_ended, self._before_start = on_signed_in, on_ended, before_start
        self.link_ttl, self.max_links, self.links_per_hour, self.max_starts = (
            link_ttl, max_links, links_per_hour, max_starts,
        )  # fmt: skip
        self._address, self._clock = client_address, clock
        self._links: dict[str, Link] = {}
        self._made: dict[str, collections.deque] = {}
        self._misses = Misses()
        self._lock = threading.Lock()
        self._hooks = threading.Lock()  # one hook at a time: a check and the write that follows go together

    # -- links ----------------------------------------------------------------------------------------------------

    def create(self, key: str, *, params: dict[str, Any] | None = None, label: str | None = None) -> Link:
        """A link for ``key`` (what it signs in: an account, a site); it replaces any open link of that key.
        ``params`` go to the login service with each start; ``label`` is what the page names (default: the key)."""
        now = self._clock()
        with self._lock:
            made = self._made.setdefault(key, collections.deque())
            while made and now - made[0] > 3600:
                made.popleft()
            if len(made) >= self.links_per_hour:
                raise LinkLimited(key)
            made.append(now)
            self._expire(now)
            replaced = [link for link in self._links.values() if link.key == key]
            for link in replaced:
                self._links.pop(link.id, None)
                link.closed = True
            while len(self._links) >= self.max_links:
                oldest = self._links.pop(min(self._links.values(), key=lambda link: link.created).id)
                oldest.closed = True
                replaced.append(oldest)
            link_id = secrets.token_urlsafe(24)
            link = Link(link_id, key, now, now + self.link_ttl, f"{self.public_url}/{link_id}", dict(params or {}),
                        key if label is None else label)  # fmt: skip
            self._links[link.id] = link
        for old in replaced:
            threading.Thread(target=self._retire, args=(old,), daemon=True).start()
        log.info("a sign-in link for %s", key)
        return link

    def links(self, key: str) -> list[Link]:
        """The open links of ``key``."""
        with self._lock:
            self._expire(self._clock())
            return [link for link in self._links.values() if link.key == key]

    def _expire(self, now: float) -> None:
        for link in [x for x in self._links.values() if now > x.expires]:
            self._links.pop(link.id, None)
            link.closed = True
            threading.Thread(target=self._retire, args=(link,), daemon=True).start()

    def find(self, link_id: str, address: str) -> Link | str:
        """The open link with this id, else "expired", or "limited" once this address asked for too many ids that
        do not exist. A real link always works: misses never lock anyone out of their own link."""
        now = self._clock()
        with self._lock:
            self._expire(now)
            link = self._links.get(link_id) if LINK_ID.match(link_id or "") else None
            if link is not None:
                return link
            allowed = self._misses.allowed(address, now)
            self._misses.record(address, now)
            return "expired" if allowed else "limited"

    def _retire(self, link: Link) -> None:
        """Close a replaced or expired link's window, once any start or poll on it has finished."""
        with link.lock:
            self._close(link)

    def _close(self, link: Link) -> None:
        """Close the link's window, if one is open (hold ``link.lock``)."""
        if link.window_id:
            try:
                self.backend.close(link.window_id)
            except LoginUnavailable:
                pass
        link.window_id, link.view_token = None, None
        if link.state in ACTIVE:
            link.state = "cancelled"

    # -- the sign-in ----------------------------------------------------------------------------------------------

    def usable(self, link: Link) -> bool:
        return link.state not in FINAL and (link.starts < self.max_starts or link.state in ACTIVE)

    def start(self, link: Link, layout: str) -> None:
        with link.lock:
            if link.closed or link.state in ACTIVE or link.state in FINAL or link.starts >= self.max_starts:
                return
            if self._before_start is not None:
                with self._hooks:
                    try:
                        refused = self._before_start(link)
                    except Exception as exc:
                        log.warning("%s: the start hook failed: %s", link.key, type(exc).__name__)
                        refused = "failed"
                if refused is not None:
                    link.state = refused if refused in self.text.outcomes else "failed"
                    return
            link.starts += 1
            try:
                window = self.backend.start(layout if layout in ("phone", "desktop") else "desktop", **link.params)
            except LoginBusy:
                link.state = "busy"
                return
            except LoginUnavailable:
                link.state = "failed"
                return
            link.window_id, link.view_token, link.state, link.host = window["id"], window["view_token"], "starting", ""
            log.info("%s opened a sign-in window", link.key)

    def advance(self, link: Link) -> None:
        """Follow the window; once it ends, run the hook that says how it went."""
        if not link.lock.acquire(blocking=False):
            return  # another poll is already on it
        try:
            if link.state not in ACTIVE or link.window_id is None:
                return
            try:
                window = self.backend.state(link.window_id)
            except LoginUnavailable:
                link.state = "failed"
                return
            link.host = str(window.get("host") or "")[:100]
            state = str(window.get("state") or "")
            if state in ACTIVE:
                link.state = state
                return
            window_id, link.window_id, link.view_token = link.window_id, None, None
            if state == "signed_in":
                try:
                    session = self.backend.result(window_id)
                except LoginUnavailable:
                    session = None
                outcome = self._run_hook(self._on_signed_in, link, session) if session else "failed"
            else:
                outcome = self._run_hook(self._on_ended or self._kept, link, window)
            link.state = outcome
            log.info("%s: sign-in %s", link.key, outcome)
        finally:
            link.lock.release()

    def _kept(self, link: Link, window: dict[str, Any]) -> str:
        state = str(window.get("state") or "")
        return state if state in self.text.outcomes and state not in ("expired", "limited") else "failed"

    def _run_hook(self, hook: Callable[[Link, dict[str, Any]], str] | None, link: Link, data: dict[str, Any]) -> str:
        if hook is None:
            return "failed"
        with self._hooks:
            try:
                outcome = hook(link, data)
            except Exception as exc:  # the hook's own failure: nothing is known to be stored
                log.warning("%s: the sign-in hook failed: %s", link.key, type(exc).__name__)
                return "failed"
        return outcome if outcome in self.text.outcomes and outcome not in ("expired", "limited") else "failed"

    def cancel(self, link: Link) -> None:
        with link.lock:
            if link.state in ("starting", "waiting"):
                self._close(link)

    # -- HTTP -----------------------------------------------------------------------------------------------------

    def routes(self, prefix: str = "") -> list[BaseRoute]:
        """The link routes under ``prefix`` (e.g. ``/connect``; it must match ``public_url``'s path when mounted at
        the root). Keep them outside your server's bearer check."""
        prefix = prefix.rstrip("/")

        async def lookup(request: Request) -> Link | Response:
            link = self.find(request.path_params["id"], self._address(request))
            if isinstance(link, Link):
                return link
            return JSONResponse({"state": link}, status_code=429 if link == "limited" else 404, headers=HEADERS)

        async def body(request: Request) -> dict[str, Any]:
            try:
                data = await request.json()
            except ValueError:
                return {}
            return data if isinstance(data, dict) else {}

        def reply(link: Link) -> JSONResponse:
            return JSONResponse(link.public(), headers=HEADERS)

        async def page(request: Request) -> Response:
            link = self.find(request.path_params["id"], self._address(request))
            if not isinstance(link, Link) or not self.usable(link):
                status = 429 if link == "limited" else 404
                return HTMLResponse(render(self.text, None), status_code=status, headers=PAGE_HEADERS)
            return HTMLResponse(render(self.text, link.label), headers=PAGE_HEADERS)

        async def start(request: Request) -> Response:
            link = await lookup(request)
            if isinstance(link, Response):
                return link
            layout = str((await body(request)).get("layout"))
            await anyio.to_thread.run_sync(self.start, link, layout)
            return reply(link)

        async def state(request: Request) -> Response:
            link = await lookup(request)
            if isinstance(link, Response):
                return link
            await anyio.to_thread.run_sync(self.advance, link)
            return reply(link)

        async def cancel(request: Request) -> Response:
            link = await lookup(request)
            if not isinstance(link, Response):
                await anyio.to_thread.run_sync(self.cancel, link)
            return Response(status_code=204, headers=HEADERS)

        async def novnc(request: Request) -> Response:
            link = await lookup(request)
            if isinstance(link, Response):
                return Response(status_code=404, headers=HEADERS)
            path = request.path_params["path"]
            if path == "paste.js":
                return Response(PASTE_JS, media_type="text/javascript", headers=HEADERS)
            status, content, content_type = await anyio.to_thread.run_sync(self.backend.static, path)
            if path == "vnc.html" and status == 200:
                content = with_paste(content)
            headers = {**HEADERS, "X-Frame-Options": "SAMEORIGIN"}
            return Response(content, status_code=status, media_type=content_type or None, headers=headers)

        async def vnc(ws: WebSocket) -> None:
            link = self.find(ws.path_params["id"], self._address(ws))
            if not isinstance(link, Link) or link.state != "waiting" or not link.window_id or not link.view_token:
                await ws.close(code=4404)
                return
            await ws.accept(subprotocol="binary" if "binary" in ws.scope.get("subprotocols", []) else None)
            try:
                await self.backend.bridge(link.window_id, link.view_token, ws)
            except LoginUnavailable:
                pass

        return [
            Route(prefix + "/{id}", page, methods=["GET"]),
            Route(prefix + "/{id}/start", start, methods=["POST"]),
            Route(prefix + "/{id}/state", state, methods=["GET"]),
            Route(prefix + "/{id}/cancel", cancel, methods=["POST"]),
            Route(prefix + "/{id}/novnc/{path:path}", novnc, methods=["GET"]),
            WebSocketRoute(prefix + "/{id}/vnc", vnc),
        ]

    def app(self) -> Starlette:
        """The routes as an app of their own, to mount where ``public_url`` points."""
        return Starlette(routes=self.routes())


def with_paste(page: bytes) -> bytes:
    """noVNC's own vnc.html, unchanged but for the paste add-on (``static/paste.js``) loaded beside its UI."""
    if b"</head>" not in page:
        return page
    return page.replace(b"</head>", PASTE_TAG + b"\n</head>", 1)
