"""Sign-in links, served by your MCP server: a person signs in to their own account from any browser.

``Relay.create(key)`` makes a link ``<public_url>/<id>``: an unguessable id (192 random bits) that works for
``link_ttl`` and one successful sign-in. Its page (``signin_window.page``) shows the site's own sign-in page, running
in a window of your login service (``signin_window.service``) and viewed through noVNC; this relay carries the
viewer's files and its live view, so the login service never faces the internet. Nothing here is behind your
server's MCP bearer. Without ``authorize`` the id is the credential; authenticated hosts also enforce
their own session and policy on every operation. A newer link for the same key replaces the older one.

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

import asyncio
import collections
import contextlib
import inspect
import logging
import re
import secrets
import threading
import time
from collections.abc import Callable, Collection, Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from importlib import resources
from typing import Any, Literal, Protocol
from urllib.parse import urlsplit

import anyio.to_thread
from starlette.applications import Starlette
from starlette.requests import HTTPConnection, Request
from starlette.responses import HTMLResponse, JSONResponse, Response
from starlette.routing import BaseRoute, Route, WebSocketRoute
from starlette.websockets import WebSocket, WebSocketDisconnect

from ._identity import stamp
from .client import LoginBusy, LoginUnavailable
from .page import PageText, render

log = logging.getLogger("signin_window")

LINK_ID = re.compile(r"[A-Za-z0-9_-]{32,64}\Z")
FIELD = re.compile(r"[a-z_][a-z0-9_]{0,39}\Z")
ACTIVE = ("starting", "waiting", "saving")
CANCELLABLE = ("starting", "waiting")
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

    def static(self, path: str, window_id: str | None = None) -> tuple[int, bytes, str]: ...  # for the link's window

    async def bridge(self, window_id: str, view_token: str, ws: Any) -> None: ...


class LinkLimited(Exception):
    """Too many links for this key this hour."""


@dataclass(frozen=True)
class AttemptContext:
    """Host-assigned opaque references, never public fields or backend parameters.

    The host authenticates callers and interprets these references. Neither an
    identity provider nor an account/permission model is imposed by the library.
    """

    owner: str
    requester: str = ""
    target: str = ""


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
    closing: bool = False  # cancellation/retirement pending backend confirmation
    viewer_revoked: bool = False  # live viewer access revoked for the current window
    next_poll: float = 0.0
    poll_failures: int = 0
    lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    context: AttemptContext | None = field(default=None, repr=False)
    layout: str = ""
    _purged: bool = field(default=False, repr=False)
    _drain_fences: int = field(default=0, repr=False)

    def show(self, **fields: object) -> None:
        """Public fields of the link's state, for its page (never a secret: the page is the id's holder's)."""
        for name, value in fields.items():
            if FIELD.match(name) and name not in ("state", "host", "layout", "can_restart", "closing"):
                self.shown[name] = str(value)[:100]

    def public(self) -> dict[str, Any]:
        data: dict[str, Any] = {**self.shown, "state": self.state, "host": self.host}
        if self.layout:
            data["layout"] = self.layout
        if self.closing:
            data["closing"] = True
        return data

    @property
    def expires_at(self) -> str:
        return datetime.fromtimestamp(self.expires, UTC).isoformat(timespec="seconds")


@dataclass
class SlotReservation:
    """Binding capacity and hourly-quota reservation handle for a key.

    Use as a context manager or call ``release()`` explicitly. Passing the
    handle to ``Relay.create(..., reservation=...)`` or ``Relay.replace()``
    consumes one reserved unit; any unconsumed units are released on context
    exit or explicit ``release()`` (idempotent).
    """

    key: str
    count: int = 1
    _relay: Relay | None = field(default=None, repr=False, compare=False)
    _remaining: int = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self.count < 1:
            raise ValueError("count must be at least 1")
        self._remaining = self.count

    @property
    def active(self) -> bool:
        """True while at least one reserved unit remains unconsumed and unreleased."""
        return self._remaining > 0

    @property
    def remaining(self) -> int:
        return self._remaining

    def release(self) -> None:
        """Release any unconsumed capacity and hourly-quota reservation (idempotent)."""
        if self._relay is not None:
            self._relay._release_reservation(self)

    def __enter__(self) -> SlotReservation:
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.release()


@dataclass(frozen=True)
class LinkSpec:
    """Parameters for creating a replacement link via ``Relay.replace()``."""

    params: dict[str, Any] | None = None
    label: str | None = None
    context: AttemptContext | None = None


@dataclass(frozen=True)
class ReplaceResult:
    """Structured outcome of ``Relay.replace()``."""

    outcome: Literal["created", "stale_target", "saving", "completed", "closing"]
    link: Link | None = None
    preserved: Link | None = None
    drained: tuple[Link, ...] = ()
    still_open: tuple[Link, ...] = ()

    @property
    def created(self) -> bool:
        return self.outcome == "created" and self.link is not None


@dataclass(frozen=True)
class DrainResult:
    """Structured outcome of ``Relay.drain_and_purge()``."""

    purged: tuple[Link, ...] = ()
    preserved: tuple[Link, ...] = ()
    still_open: tuple[Link, ...] = ()

    @property
    def drained(self) -> tuple[Link, ...]:
        return self.purged


@dataclass(frozen=True)
class KeySnapshot:
    """Non-blocking snapshot of a key's active, retired, and draining state."""

    key: str
    active: tuple[Link, ...]
    retired: tuple[Link, ...]
    draining: bool

    @property
    def links(self) -> tuple[Link, ...]:
        """All tracked links for this key (active first, then retired not already in active)."""
        seen = {link.id for link in self.active}
        return self.active + tuple(link for link in self.retired if link.id not in seen)

    @property
    def has_saving(self) -> bool:
        return any(link.state == "saving" for link in self.links)


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
        authorize: Callable[[HTTPConnection, Link, str], Any] | None = None,
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
        self._authorize = authorize
        parts = urlsplit(public_url)
        self._origin = f"{parts.scheme}://{parts.netloc}"
        self._links: dict[str, Link] = {}
        self._retired: dict[str, Link] = {}
        self._made: dict[str, collections.deque] = {}
        self._reserved_slots: int = 0
        self._reserved_quota: dict[str, int] = {}
        self._draining: dict[str, int] = {}
        self._misses = Misses()
        self._lock = threading.Lock()
        self._hooks = threading.Lock()  # one hook at a time: a check and the write that follows go together

    # -- links ----------------------------------------------------------------------------------------------------

    @contextlib.asynccontextmanager
    async def lifespan(self):
        """Reconcile completion and expiry without a connected page.

        Mount once when using ``routes``; ``app`` installs this automatically.
        Backends and hooks must honor their own bounded I/O timeouts.
        """

        stop = asyncio.Event()

        async def follow():
            while not stop.is_set():
                await anyio.to_thread.run_sync(self.tick)
                with self._lock:
                    has_work = bool(self._retired) or any(
                        link.state in ACTIVE and link.window_id is not None for link in self._links.values()
                    )
                with contextlib.suppress(TimeoutError):
                    await asyncio.wait_for(stop.wait(), timeout=0.25 if has_work else 1.0)

        task = asyncio.create_task(follow())
        try:
            yield self
        finally:
            stop.set()
            await task  # never abandon a completion hook in a worker during shutdown

    def tick(self) -> None:
        now = self._clock()
        with self._lock:
            self._expire(now)
            links = list(self._links.values())
            retired = list(self._retired.values())
        for link in links:
            if not link.closing and link.next_poll <= now:
                self.advance(link)
        for link in retired:
            if link._purged:
                with self._lock:
                    self._retired.pop(link.id, None)
                continue
            if link.next_poll <= now:
                if link.closing:
                    self._retire(link)
                else:
                    self.advance(link)
            if link.lock.acquire(blocking=False):
                try:
                    if link._purged or (not link.closing and (link.state not in ACTIVE or link.window_id is None)):
                        with self._lock:
                            self._retired.pop(link.id, None)
                finally:
                    link.lock.release()

    def _track_retired_locked(self, link: Link, *, reset_poll: bool = True) -> list[Link]:
        if link._purged:
            return []
        if reset_poll:
            link.next_poll = 0.0
        self._retired[link.id] = link
        return []

    def _prune_made_locked(self, key: str, now: float) -> collections.deque:
        made = self._made.setdefault(key, collections.deque())
        while made and now - made[0] > 3600:
            made.popleft()
        return made

    def _release_reservation(self, reservation: SlotReservation) -> None:
        with self._lock:
            rem = reservation._remaining
            if rem <= 0:
                return
            reservation._remaining = 0
            self._reserved_slots = max(0, self._reserved_slots - rem)
            remaining_quota = self._reserved_quota.get(reservation.key, 0) - rem
            if remaining_quota > 0:
                self._reserved_quota[reservation.key] = remaining_quota
            else:
                self._reserved_quota.pop(reservation.key, None)

    def _consume_reservation_locked(self, key: str, reservation: SlotReservation) -> None:
        if reservation._relay is not self or reservation.key != key:
            raise ValueError("reservation does not match this relay and key")
        if reservation._remaining <= 0:
            raise ValueError("reservation already consumed or released")
        reservation._remaining -= 1
        self._reserved_slots = max(0, self._reserved_slots - 1)
        remaining_quota = self._reserved_quota.get(key, 0) - 1
        if remaining_quota > 0:
            self._reserved_quota[key] = remaining_quota
        else:
            self._reserved_quota.pop(key, None)

    def _refund_quota_locked(self, key: str, created_ts: float) -> None:
        made = self._made.get(key)
        if not made:
            return
        for idx in range(len(made) - 1, -1, -1):
            if made[idx] == created_ts:
                del made[idx]
                break
        if not made:
            self._made.pop(key, None)

    def _create_locked(
        self,
        key: str,
        now: float,
        *,
        params: dict[str, Any] | None = None,
        label: str | None = None,
        context: AttemptContext | None = None,
        reservation: SlotReservation | None = None,
    ) -> tuple[Link, list[Link]]:
        made = self._prune_made_locked(key, now)
        if reservation is not None:
            self._consume_reservation_locked(key, reservation)
            self._expire(now)
        else:
            if len(made) + self._reserved_quota.get(key, 0) >= self.links_per_hour:
                raise LinkLimited(key)
            self._expire(now)
            if len(self._retired) + self._reserved_slots >= self.max_links:
                raise LinkLimited(key)
        made.append(now)
        to_retire: list[Link] = []
        replaced = [link for link in self._links.values() if link.key == key]
        for link in replaced:
            self._links.pop(link.id, None)
            link.closed = True
            link.view_token = None
            if link.window_id is not None:
                self._track_retired_locked(link)
                if link.state != "saving":
                    to_retire.append(link)
        while len(self._links) >= self.max_links:
            oldest = self._links.pop(min(self._links.values(), key=lambda link: link.created).id)
            oldest.closed = True
            oldest.view_token = None
            if oldest.window_id is not None:
                self._track_retired_locked(oldest)
                if oldest.state != "saving":
                    to_retire.append(oldest)
        link_id = secrets.token_urlsafe(24)
        link = Link(
            link_id,
            key,
            now,
            now + self.link_ttl,
            f"{self.public_url}/{link_id}",
            dict(params or {}),
            key if label is None else label,
        )
        link.context = context
        self._links[link.id] = link
        return link, to_retire

    def _rollback_link(self, link: Link) -> None:
        with self._lock:
            link.closed = True
            link._purged = True
            link.view_token = None
            self._links.pop(link.id, None)
            self._retired.pop(link.id, None)
            self._refund_quota_locked(link.key, link.created)
        self._retire(link)

    def _drain_link(self, link: Link, completed_states: Collection[str]) -> tuple[bool, bool, bool]:
        """Cancel ``link`` if cancellable and return ``(still_open, is_saving, is_completed)``."""
        self.cancel(link)
        with link.lock:
            is_saving = link.state == "saving"
            still_open = link.window_id is not None or link.closing or link.state in ACTIVE
            is_completed = link.state in completed_states
            return still_open, is_saving, is_completed

    def _is_fenced(self, link: Link, *, locked: bool = False) -> bool:
        """Return True if ``link`` is permanently closed or transiently fenced by an active drain."""
        if locked:
            return link.closed or link._drain_fences > 0
        with self._lock:
            return link.closed or link._drain_fences > 0

    def _exit_draining(self, key: str) -> None:
        with self._lock:
            remaining = self._draining.get(key, 0) - 1
            if remaining > 0:
                self._draining[key] = remaining
            else:
                self._draining.pop(key, None)

    def reserve(self, key: str, *, count: int = 1) -> SlotReservation:
        """Atomically reserve capacity and hourly quota for ``key``.

        Returns a ``SlotReservation`` context manager whose unconsumed units are
        released on exit or explicit ``release()``. Raises ``LinkLimited`` if
        capacity or hourly quota is exhausted.
        """
        if count < 1:
            raise ValueError("count must be at least 1")
        now = self._clock()
        with self._lock:
            made = self._prune_made_locked(key, now)
            if len(made) + self._reserved_quota.get(key, 0) + count > self.links_per_hour:
                raise LinkLimited(key)
            self._expire(now)
            if len(self._retired) + self._reserved_slots + count > self.max_links:
                raise LinkLimited(key)
            self._reserved_slots += count
            self._reserved_quota[key] = self._reserved_quota.get(key, 0) + count
        return SlotReservation(key=key, count=count, _relay=self)

    def is_draining(self, key: str) -> bool:
        """Return True while a ``replace`` or ``drain_and_purge`` is in progress for ``key``."""
        with self._lock:
            return self._draining.get(key, 0) > 0

    def snapshot(self, key: str) -> KeySnapshot:
        """Non-blocking snapshot of active, retired, and draining state for ``key``.

        Never acquires ``link.lock``, so status reads cannot block while
        ``backend.close()`` or a hook is running.
        """
        now = self._clock()
        with self._lock:
            self._expire(now)
            active = tuple(link for link in self._links.values() if link.key == key)
            retired = tuple(link for link in self._retired.values() if link.key == key)
            draining = self._draining.get(key, 0) > 0
        return KeySnapshot(key=key, active=active, retired=retired, draining=draining)

    def create(
        self,
        key: str,
        *,
        params: dict[str, Any] | None = None,
        label: str | None = None,
        context: AttemptContext | None = None,
        reservation: SlotReservation | None = None,
    ) -> Link:
        """A link for ``key`` (what it signs in: an account, a site); it replaces any open link of that key.
        ``params`` go to the login service with each start; ``label`` is what the page names (default: the key)."""
        if self._authorize is not None and (context is None or not context.owner):
            raise ValueError("authenticated links require a host-assigned owner")
        now = self._clock()
        with self._lock:
            link, to_retire = self._create_locked(
                key,
                now,
                params=params,
                label=label,
                context=context,
                reservation=reservation,
            )
        for old in to_retire:
            threading.Thread(target=self._retire, args=(old,), daemon=True).start()
        log.info("a sign-in link for %s", key)
        return link

    def replace(
        self,
        key: str,
        spec: LinkSpec | None = None,
        *,
        replace_id: str | None = None,
        completed_states: Collection[str] = FINAL,
        known_completed: Collection[str] | None = None,
        on_commit: Callable[[Link], Any] | None = None,
        reservation: SlotReservation | None = None,
        extra_links: Iterable[Link] = (),
    ) -> ReplaceResult:
        """Fenced drain-and-replace lifecycle for ``key``.

        Atomically reserves capacity and hourly quota (unless ``reservation`` is
        provided), validates optional ``replace_id``, protects ``saving`` and
        in-flight ``completed_states`` links, drains prior links outside
        ``self._lock``, rechecks post-drain state, creates the replacement link,
        and invokes optional ``on_commit`` (rolling back the new link and its
        quota if ``on_commit`` raises).

        When ``known_completed`` is provided, it restricts the set of
        already-idle completed links of ``key`` (excluding ``replace_id``) that
        the caller already observed; any other link found in
        ``completed_states`` yields outcome ``"completed"``. When ``None``
        (default), all already-idle completed links at entry are treated as
        known.

        Candidate links are transiently fenced against new starts and viewer
        access during the drain rather than marked ``closed`` up front; only
        links that are actually drained, replaced, or left with a requested
        teardown still in flight become permanently closed. ``saving`` and
        newly completed survivors stay open.
        """
        link_spec = spec or LinkSpec()
        if self._authorize is not None and (link_spec.context is None or not link_spec.context.owner):
            raise ValueError("authenticated links require a host-assigned owner")
        own_reservation: SlotReservation | None = None
        if reservation is None:
            own_reservation = self.reserve(key)
            active_res = own_reservation
        else:
            if reservation._relay is not self or reservation.key != key:
                raise ValueError("reservation does not match this relay and key")
            if reservation._remaining <= 0:
                raise ValueError("reservation already consumed or released")
            active_res = reservation

        draining_entered = False
        previous: list[Link] = []
        fenced: list[Link] = []
        drained_links: list[Link] = []
        try:
            now = self._clock()
            with self._lock:
                self._expire(now)
                seen: dict[str, Link] = {}
                for item in self._links.values():
                    if item.key == key:
                        seen[item.id] = item
                for item in self._retired.values():
                    if item.key == key:
                        seen[item.id] = item
                for item in extra_links:
                    if item.key == key:
                        seen[item.id] = item
                previous = list(seen.values())

                if replace_id is not None:
                    target = self._links.get(replace_id)
                    if (
                        target is None
                        or target.key != key
                        or self._is_fenced(target, locked=True)
                        or target.state not in ("ready", "starting", "waiting")
                    ):
                        preserved = target if (target is not None and target.key == key) else None
                        return ReplaceResult(outcome="stale_target", preserved=preserved)

                saving_pre = next((old for old in previous if old.state == "saving"), None)
                if saving_pre is not None:
                    return ReplaceResult(outcome="saving", preserved=saving_pre, still_open=(saving_pre,))

                self._draining[key] = self._draining.get(key, 0) + 1
                draining_entered = True
                for old in previous:
                    old._drain_fences += 1
                    fenced.append(old)

            idle_completed: set[str] = set()
            for old in previous:
                if old.id == replace_id:
                    continue
                if old.lock.acquire(blocking=False):
                    try:
                        if old.window_id is None and not old.closing and old.state in completed_states:
                            idle_completed.add(old.id)
                    finally:
                        old.lock.release()
            already_completed = idle_completed if known_completed is None else idle_completed & set(known_completed)

            still_open_links: list[Link] = []
            saving_link: Link | None = None
            completed_link: Link | None = None
            for old in previous:
                open_now, is_saving, is_completed = self._drain_link(old, completed_states)
                if is_saving:
                    if saving_link is None:
                        saving_link = old
                    still_open_links.append(old)
                elif open_now:
                    # Teardown was requested and is still in flight: this link is dying, not a survivor.
                    with self._lock:
                        old.closed = True
                    still_open_links.append(old)
                elif is_completed and old.id not in already_completed:
                    if completed_link is None:
                        completed_link = old
                else:
                    with self._lock:
                        old.closed = True
                    drained_links.append(old)

            if saving_link is not None:
                return ReplaceResult(
                    outcome="saving",
                    preserved=saving_link,
                    drained=tuple(drained_links),
                    still_open=tuple(still_open_links),
                )
            if still_open_links:
                return ReplaceResult(
                    outcome="closing",
                    drained=tuple(drained_links),
                    still_open=tuple(still_open_links),
                )
            if completed_link is not None:
                return ReplaceResult(
                    outcome="completed",
                    preserved=completed_link,
                    drained=tuple(drained_links),
                )

            now = self._clock()
            with self._lock:
                self._expire(now)
                if replace_id is not None:
                    newer = next(
                        (
                            item
                            for item in self._links.values()
                            if item.key == key and item.id != replace_id and not item.closed
                        ),
                        None,
                    )
                    if newer is not None:
                        return ReplaceResult(
                            outcome="stale_target",
                            preserved=newer,
                            drained=tuple(drained_links),
                        )
                for item in (*self._links.values(), *self._retired.values()):
                    if item.key != key:
                        continue
                    if item.state == "saving":
                        return ReplaceResult(
                            outcome="saving",
                            preserved=item,
                            drained=tuple(drained_links),
                            still_open=(item,),
                        )
                    if item.state in completed_states and item.id not in already_completed:
                        return ReplaceResult(
                            outcome="completed",
                            preserved=item,
                            drained=tuple(drained_links),
                        )
                new_link, to_retire = self._create_locked(
                    key,
                    now,
                    params=link_spec.params,
                    label=link_spec.label,
                    context=link_spec.context,
                    reservation=active_res,
                )

            for old in to_retire:
                threading.Thread(target=self._retire, args=(old,), daemon=True).start()
            if on_commit is not None:
                try:
                    on_commit(new_link)
                except BaseException:
                    self._rollback_link(new_link)
                    raise
            log.info("a sign-in link for %s", key)
            return ReplaceResult(outcome="created", link=new_link, drained=tuple(drained_links))
        finally:
            if fenced:
                with self._lock:
                    for old in fenced:
                        old._drain_fences -= 1
            if draining_entered:
                self._exit_draining(key)
            if own_reservation is not None:
                own_reservation.release()

    def drain_and_purge(
        self,
        key: str,
        *,
        predicate: Callable[[Link], bool] | None = None,
        before_purge: Callable[[], Any] | None = None,
        extra_links: Iterable[Link] = (),
        force: bool = False,
    ) -> DrainResult:
        """Drain matching links for ``key`` and purge finished ones from ``_links`` and ``_retired``.

        Purged links are marked ``_purged = True`` so concurrent ``_retire()``
        or ``tick()`` calls cannot re-insert them into ``_retired``.

        Links that are ``saving`` are always preserved (even when ``force=True``)
        so an in-flight credential hand-over is not orphaned. Every matching
        link, ``saving`` ones included, is transiently fenced against new
        starts and viewer access during the drain rather than marked ``closed``
        up front; the fence does not interrupt a hand-over in progress. When
        ``force=False`` (default), links that remain open after the drain
        attempt are reported in ``still_open`` and marked ``closed``: their
        teardown was requested and they are no longer usable sign-ins.
        When ``force=True``, non-``saving`` links that remain open after the
        drain attempt are force-closed, their view tokens are revoked, and they
        are marked closed/purged and removed from active and retired tracking.
        """
        with self._lock:
            self._draining[key] = self._draining.get(key, 0) + 1
        fenced: list[Link] = []
        try:
            now = self._clock()
            with self._lock:
                self._expire(now)
                seen: dict[str, Link] = {}
                for item in self._links.values():
                    if item.key == key:
                        seen[item.id] = item
                for item in self._retired.values():
                    if item.key == key:
                        seen[item.id] = item
                for item in extra_links:
                    if item.key == key:
                        seen[item.id] = item
                candidates = list(seen.values())

            targets = [link for link in candidates if predicate is None or predicate(link)]
            with self._lock:
                for link in targets:
                    # Fence saving links too: one that fails out of saving must not start a new window mid-purge.
                    link._drain_fences += 1
                    fenced.append(link)

            to_purge: list[Link] = []
            preserved: list[Link] = []
            still_open: list[Link] = []
            for link in targets:
                with link.lock:
                    if link.state == "saving":
                        preserved.append(link)
                        still_open.append(link)
                        continue
                    if link.state in ("starting", "waiting"):
                        self._close(link)
                    is_saving = link.state == "saving"
                    open_now = link.window_id is not None or link.closing or link.state in ACTIVE
                    if open_now and not is_saving and force:
                        self._close(link, force=True)
                        open_now = False
                if is_saving:
                    preserved.append(link)
                    still_open.append(link)
                elif open_now:
                    # Teardown was requested and is still in flight: this link is dying, not a survivor.
                    with self._lock:
                        link.closed = True
                    still_open.append(link)
                else:
                    to_purge.append(link)

            if before_purge is not None:
                before_purge()

            purged: list[Link] = []
            with self._lock:
                for link in to_purge:
                    link.closed = True
                    link._purged = True
                    link.view_token = None
                    link.viewer_revoked = True
                    self._links.pop(link.id, None)
                    self._retired.pop(link.id, None)
                    purged.append(link)
            return DrainResult(
                purged=tuple(purged),
                preserved=tuple(preserved),
                still_open=tuple(still_open),
            )
        finally:
            if fenced:
                with self._lock:
                    for link in fenced:
                        link._drain_fences -= 1
            self._exit_draining(key)

    def links(self, key: str) -> list[Link]:
        """The open links of ``key``."""
        with self._lock:
            self._expire(self._clock())
            return [link for link in self._links.values() if link.key == key]

    def _expire(self, now: float) -> None:
        for link in [x for x in self._links.values() if now > x.expires]:
            self._links.pop(link.id, None)
            link.closed = True
            if link.state == "saving" and link.window_id is not None:
                link.view_token = None
                self._track_retired_locked(link)
            else:
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

    def _retire(self, link: Link, *, force: bool = False) -> None:
        """Close a replaced or expired link's window, once any start or poll on it has finished."""
        with link.lock:
            self._close(link, force=force)

    def _backend_close(self, window_id: str, *, cancel_only: bool) -> bool:
        """Return True if a cancel/close was issued, False if the backend lacks atomic cancel_only."""
        if cancel_only:
            sig = inspect.signature(self.backend.close)
            if "cancel_only" in sig.parameters:
                self.backend.close(window_id, cancel_only=True)  # type: ignore[call-arg]
                return True
            return False
        self.backend.close(window_id)
        return True

    def _close(self, link: Link, *, force: bool = False) -> None:
        """Close the link's window, if one is open (hold ``link.lock``)."""
        # Revoke live viewer access immediately regardless of backend disposition.
        link.view_token = None
        link.viewer_revoked = True
        if not force and link.window_id is not None:
            if link.state == "saving":
                link.closing = False
                with self._lock:
                    self._track_retired_locked(link)
                return
            # Ask the backend to cancel only cancellable windows (preserving saving/signed_in
            # atomically under service._guard), then read its resulting disposition.
            try:
                issued = self._backend_close(link.window_id, cancel_only=True)
                window = self.backend.state(link.window_id)
            except LoginUnavailable:
                link.closing = True
                link.poll_failures += 1
                link.next_poll = self._clock() + min(1.0 * (2 ** min(link.poll_failures - 1, 3)), 8.0)
                with self._lock:
                    self._track_retired_locked(link, reset_poll=False)
                return
            live_state = str(window.get("state") or "")
            if live_state in ("starting", "waiting"):
                if not issued:
                    # Custom backend lacks atomic cancel_only: revoke viewer access and retain in _retired
                    # until polling observes the backend's terminal outcome (never issue an unconditional close).
                    link.closing = False
                    link.next_poll = self._clock() + 1.0
                    with self._lock:
                        self._track_retired_locked(link, reset_poll=False)
                    return
                # Backend returned before cancellation completed (e.g. 10s wait expired); keep tracking.
                link.closing = True
                link.next_poll = self._clock() + 1.0
                with self._lock:
                    self._track_retired_locked(link, reset_poll=False)
                return
            elif live_state not in ("cancelled", "closed", "unknown", ""):
                # Preserve saving, signed_in, and completed kept-session outcomes (e.g. connected) for normal hooks.
                if live_state in ("saving", "signed_in"):
                    link.state = "saving"
                link.closing = False
                with self._lock:
                    self._track_retired_locked(link)
                return
        elif link.window_id:
            try:
                self._backend_close(link.window_id, cancel_only=False)
            except LoginUnavailable:
                pass
        link.closing = False
        link.window_id = None
        link.layout = ""
        if link.state in CANCELLABLE or (force and link.state in ACTIVE):
            link.state = "cancelled"
        with self._lock:
            self._retired.pop(link.id, None)

    # -- the sign-in ----------------------------------------------------------------------------------------------

    def usable(self, link: Link) -> bool:
        return link.state not in FINAL and (link.starts < self.max_starts or link.state in ACTIVE)

    def start(self, link: Link, layout: str) -> None:
        with link.lock:
            if self._is_fenced(link) or link.state in ACTIVE or link.state in FINAL or link.starts >= self.max_starts:
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
            chosen = layout if layout in ("phone", "desktop") else "desktop"
            try:
                window = self.backend.start(chosen, **link.params)
            except LoginBusy:
                link.state = "busy"
                return
            except LoginUnavailable:
                link.state = "failed"
                return
            returned_layout = window.get("layout")
            link.window_id, link.state, link.host = window["id"], "starting", ""
            link.layout = str(returned_layout) if returned_layout in ("phone", "desktop") else chosen
            link.viewer_revoked = False
            link.view_token = str(window["view_token"]) if window.get("view_token") else None  # or in a later state
            if self._is_fenced(link):
                self._close(link)
                return
            log.info("%s opened a sign-in window", link.key)

    def advance(self, link: Link) -> None:
        """Follow the window; once it ends, run the hook that says how it went."""
        if not link.lock.acquire(blocking=False):
            return  # another poll is already on it
        try:
            if link._purged or link.closing or link.state not in ACTIVE or link.window_id is None:
                return
            now = self._clock()
            try:
                window = self.backend.state(link.window_id)
            except LoginUnavailable:
                # Keep transient backend failures recoverable across multiple retries.
                link.poll_failures += 1
                backoff = min(1.0 * (2 ** min(link.poll_failures - 1, 3)), 8.0)
                link.next_poll = now + backoff
                if link.poll_failures >= 5 and now > link.expires + 60:
                    link.window_id, link.view_token, link.layout = None, None, ""
                    link.state = "failed"
                return
            link.host = str(window.get("host") or "")[:100]
            state = str(window.get("state") or "")
            if state in ACTIVE:
                link.poll_failures = 0
                link.next_poll = now + 1.0
                link.state = state
                if window.get("layout") in ("phone", "desktop"):
                    link.layout = str(window["layout"])
                if state == "saving":
                    link.view_token = None
                elif (
                    not link.view_token
                    and not self._is_fenced(link)
                    and not link.viewer_revoked
                    and window.get("view_token")
                ):
                    link.view_token = str(window["view_token"])
                return
            window_id = link.window_id
            if state == "signed_in":
                try:
                    session = self.backend.result(window_id)
                except LoginUnavailable:
                    # Keep window_id intact for retry while within bounded failure budget.
                    link.poll_failures += 1
                    link.next_poll = now + min(1.0 * (2 ** min(link.poll_failures - 1, 3)), 8.0)
                    if link.poll_failures < 5 or now <= link.expires + 60:
                        return
                    session = None
                link.poll_failures = 0
                link.window_id, link.view_token, link.layout = None, None, ""
                outcome = self._run_hook(self._on_signed_in, link, session) if session else "failed"
            else:
                link.poll_failures = 0
                link.window_id, link.view_token, link.layout = None, None, ""
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

    def cancel(self, link: Link, *, for_restart: bool = False) -> bool:
        with link.lock:
            if for_restart and link.starts >= self.max_starts:
                return False
            if link.state in ("starting", "waiting"):
                self._close(link)
            return True

    # -- HTTP -----------------------------------------------------------------------------------------------------

    async def _allowed(self, request: HTTPConnection, link: Link, operation: str) -> bool:
        if self._authorize is None:
            return True
        if link.context is None:
            return False
        if (isinstance(request, WebSocket) or request.scope.get("method") == "POST") and (
            request.headers.get("origin") != self._origin
        ):
            return False
        try:
            decision = self._authorize(request, link, operation)
            if inspect.isawaitable(decision):
                decision = await asyncio.wait_for(decision, timeout=5)
            return decision is True
        except Exception as exc:
            log.warning("Attempt authorization failed: %s", type(exc).__name__)
            return False

    def routes(self, prefix: str = "") -> list[BaseRoute]:
        """The link routes under ``prefix`` (e.g. ``/connect``; it must match ``public_url``'s path when mounted at
        the root). Keep them outside your server's bearer check."""
        prefix = prefix.rstrip("/")

        async def lookup(request: Request) -> Link | Response:
            link = self.find(request.path_params["id"], self._address(request))
            if isinstance(link, Link) and await self._allowed(request, link, request.scope["endpoint"].__name__):
                return link
            if isinstance(link, Link):
                return JSONResponse({"state": "unavailable"}, status_code=404, headers=HEADERS)
            return JSONResponse({"state": link}, status_code=429 if link == "limited" else 404, headers=HEADERS)

        async def body(request: Request) -> dict[str, Any]:
            try:
                data = await request.json()
            except ValueError:
                return {}
            return data if isinstance(data, dict) else {}

        def reply(link: Link) -> JSONResponse:
            data = link.public()
            if link.state in CANCELLABLE:
                data["can_restart"] = link.starts < self.max_starts
                if link.viewer_revoked:
                    data["closing"] = True
            return JSONResponse(data, headers=HEADERS)

        async def page(request: Request) -> Response:
            link = self.find(request.path_params["id"], self._address(request))
            if isinstance(link, Link) and not await self._allowed(request, link, "page"):
                return HTMLResponse(
                    stamp("<h1>This sign-in request is unavailable</h1>", self.text.identity),
                    status_code=404,
                    headers=PAGE_HEADERS,
                )
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
            if isinstance(link, Response) and self._authorize is not None:
                return link
            for_restart = False
            if (request.headers.get("content-type") or "").split(";")[0].strip().lower() == "application/json":
                for_restart = bool((await body(request)).get("for_restart"))
            if not isinstance(link, Response):
                await anyio.to_thread.run_sync(lambda: self.cancel(link, for_restart=for_restart))
                if for_restart:
                    return reply(link)
            return Response(status_code=204, headers=HEADERS)

        async def novnc(request: Request) -> Response:
            link = await lookup(request)
            if isinstance(link, Response):
                return Response(status_code=404, headers=HEADERS)
            path = request.path_params["path"]
            if path == "paste.js":
                return Response(PASTE_JS, media_type="text/javascript", headers=HEADERS)
            status, content, content_type = await anyio.to_thread.run_sync(self.backend.static, path, link.window_id)
            if path == "vnc.html" and status == 200:
                content = with_paste(content)
            headers = {**HEADERS, "X-Frame-Options": "SAMEORIGIN"}
            return Response(content, status_code=status, media_type=content_type or None, headers=headers)

        async def vnc(ws: WebSocket) -> None:
            link = self.find(ws.path_params["id"], self._address(ws))
            if (
                not isinstance(link, Link)
                or self._is_fenced(link)
                or link.state != "waiting"
                or not link.window_id
                or not link.view_token
            ):
                await ws.close(code=4404)
                return
            if not await self._allowed(ws, link, "vnc"):
                await ws.close(code=4404)
                return
            await ws.accept(subprotocol="binary" if "binary" in ws.scope.get("subprotocols", []) else None)

            relay = self

            class GuardedSocket:
                def __getattr__(self, name):
                    return getattr(ws, name)

                async def receive(self):
                    message = await ws.receive()
                    if not await relay._allowed(ws, link, "vnc"):
                        raise WebSocketDisconnect(4404)
                    return message

                async def send_bytes(self, data):
                    if not await relay._allowed(ws, link, "vnc"):
                        raise WebSocketDisconnect(4404)
                    await ws.send_bytes(data)

            async def watch():
                while (
                    not self._is_fenced(link)
                    and not link.closing
                    and link.state == "waiting"
                    and link.view_token is not None
                    and await self._allowed(ws, link, "vnc")
                ):
                    await asyncio.sleep(0.25)

            tasks = []
            try:
                socket = ws if self._authorize is None else GuardedSocket()
                tasks = [
                    asyncio.create_task(self.backend.bridge(link.window_id, link.view_token, socket)),
                    asyncio.create_task(watch()),
                ]
                done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
                for task in done:
                    task.result()
            except (LoginUnavailable, WebSocketDisconnect):
                pass
            finally:
                for task in tasks:
                    task.cancel()
                if tasks:
                    await asyncio.gather(*tasks, return_exceptions=True)
                with contextlib.suppress(Exception):
                    await ws.close()

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

        @contextlib.asynccontextmanager
        async def lifespan(_app):
            async with self.lifespan():
                yield

        return Starlette(routes=self.routes(), lifespan=lifespan)


def with_paste(page: bytes) -> bytes:
    """noVNC's own vnc.html, unchanged but for the paste add-on (``static/paste.js``) loaded beside its UI (once: a
    viewer that already loads it keeps its one tag, or each paste would be typed twice)."""
    if b"</head>" not in page or PASTE_TAG in page:
        return page
    return page.replace(b"</head>", PASTE_TAG + b"\n</head>", 1)
