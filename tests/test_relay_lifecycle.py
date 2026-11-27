"""Deterministic concurrency and lifecycle tests for Relay.reserve, replace, drain_and_purge, and snapshot."""

from __future__ import annotations

import asyncio
import threading
from collections.abc import Callable
from typing import Any

import pytest
from starlette.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from signin_window.client import LoginUnavailable
from signin_window.page import PageText
from signin_window.relay import (
    AttemptContext,
    DrainResult,
    KeySnapshot,
    Link,
    LinkLimited,
    LinkSpec,
    Relay,
    ReplaceResult,
    SlotReservation,
)


class ControlledBackend:
    """Backend with explicit Event hooks for deterministic race reproduction."""

    def __init__(self) -> None:
        self.started: list[tuple[str, dict[str, Any]]] = []
        self.closed: list[tuple[str, bool]] = []
        self.states: dict[str, dict[str, Any]] = {}
        self.results: dict[str, dict[str, Any]] = {}
        self.on_close: Callable[[str, bool], None] | None = None
        self.on_state: Callable[[str], dict[str, Any] | None] | None = None
        self.on_bridge: Callable[[str, str, Any], Any] | None = None

    def start(self, layout: str = "desktop", **params: Any) -> dict[str, Any]:
        window_id = f"win-{len(self.started):06d}"
        self.started.append((layout, params))
        self.states[window_id] = {"state": "waiting", "host": "accounts.example.com"}
        return {"id": window_id, "state": "starting", "view_token": "t" * 24}

    def state(self, window_id: str) -> dict[str, Any]:
        if self.on_state is not None:
            override = self.on_state(window_id)
            if override is not None:
                return override
        return self.states.get(window_id, {"state": "unknown"})

    def result(self, window_id: str) -> dict[str, Any] | None:
        return self.results.pop(window_id, None)

    def close(self, window_id: str, *, cancel_only: bool = False) -> None:
        self.closed.append((window_id, cancel_only))
        if self.on_close is not None:
            self.on_close(window_id, cancel_only)
            return
        cur = self.states.get(window_id, {}).get("state")
        if cur in ("starting", "waiting"):
            self.states[window_id] = {"state": "cancelled"}
        elif not cancel_only and cur == "signed_in":
            self.results.pop(window_id, None)
            self.states[window_id] = {"state": "closed"}

    def static(self, path: str, window_id: str | None = None) -> tuple[int, bytes, str]:
        return 404, b"", "text/plain"

    async def bridge(self, window_id: str, view_token: str, ws: Any) -> None:
        if self.on_bridge is not None:
            await self.on_bridge(window_id, view_token, ws)
            return None
        return None


class Clock:
    def __init__(self, now: float = 1_000_000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


def make_relay(
    backend: ControlledBackend | None = None,
    clock: Clock | None = None,
    **kwargs: Any,
) -> tuple[Relay, ControlledBackend, Clock]:
    be = backend or ControlledBackend()
    clk = clock or Clock()
    text = PageText(service="Example").with_outcomes(
        connected="<h1>Connected</h1>",
        verifying="<h1>Verifying</h1>",
    )
    kwargs.setdefault("text", text)
    relay = Relay(be, "https://mcp.example.com/connect", clock=clk, **kwargs)
    return relay, be, clk


def open_window(relay: Relay, link: Link) -> str:
    relay.start(link, "desktop")
    relay.advance(link)
    if link.window_id is None:
        raise AssertionError("expected window_id after start")
    return link.window_id


# ---------------------------------------------------------------------------
# Race Class 1: Reservation & quota leaks on error, cancellation, on_commit
# ---------------------------------------------------------------------------


def test_reserve_binds_hourly_quota_and_capacity_and_rolls_back_on_error_and_cancellation():
    relay, _, _ = make_relay(max_links=1, links_per_hour=1)

    with pytest.raises(ValueError):
        relay.reserve("alice", count=0)

    # Binding reservation blocks both another reserve() and an unreserved create() across keys (capacity)
    # and for the same key (hourly quota).
    with pytest.raises(RuntimeError):
        with relay.reserve("alice") as res:
            assert isinstance(res, SlotReservation)
            assert res.active and res.remaining == 1
            with pytest.raises(LinkLimited):
                relay.reserve("alice")
            with pytest.raises(LinkLimited):
                relay.create("alice")
            with pytest.raises(LinkLimited):
                relay.reserve("bob")
            with pytest.raises(LinkLimited):
                relay.create("bob")
            raise RuntimeError("pre-create failure")

    assert not res.active and res.remaining == 0

    # BaseException (e.g. asyncio.CancelledError) also rolls back cleanly.
    with pytest.raises(asyncio.CancelledError):
        with relay.reserve("alice") as res2:
            raise asyncio.CancelledError()
    assert not res2.active

    # Explicit idempotent release also works and restores full quota & capacity.
    res3 = relay.reserve("alice")
    res3.release()
    res3.release()
    link = relay.create("alice")
    assert link.key == "alice"


def test_concurrent_reserve_enforces_hourly_quota_under_barrier():
    relay, _, _ = make_relay(max_links=10, links_per_hour=1)
    workers = 6
    barrier = threading.Barrier(workers)
    acquired: list[SlotReservation] = []
    limited = 0
    guard = threading.Lock()

    def worker() -> None:
        nonlocal limited
        barrier.wait(timeout=5)
        try:
            res = relay.reserve("alice")
        except LinkLimited:
            with guard:
                limited += 1
            return
        with guard:
            acquired.append(res)

    threads = [threading.Thread(target=worker) for _ in range(workers)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=5)

    assert len(acquired) == 1
    assert limited == workers - 1
    acquired[0].release()
    # After release, quota is available again.
    with relay.reserve("alice") as res:
        link = relay.create("alice", reservation=res)
        assert not res.active
        assert link.key == "alice"


def test_replace_on_commit_failure_and_cancellation_rolls_back_link_and_quota():
    relay, backend, _ = make_relay(max_links=2, links_per_hour=1)
    seen_links: list[Link] = []

    def fail_commit(link: Link) -> None:
        seen_links.append(link)
        # Even if a window opened before commit raised, rollback must close it.
        open_window(relay, link)
        raise RuntimeError("commit failed")

    with pytest.raises(RuntimeError, match="commit failed"):
        relay.replace("alice", LinkSpec(label="Alice"), on_commit=fail_commit)

    assert len(seen_links) == 1
    rolled_back = seen_links[0]
    assert rolled_back.closed is True
    assert rolled_back._purged is True
    assert not relay.is_draining("alice")
    snap = relay.snapshot("alice")
    assert snap.active == () and snap.retired == () and snap.draining is False
    assert len(backend.closed) == 1

    # Also verify BaseException (CancelledError) inside on_commit refunds quota.
    def cancel_commit(_link: Link) -> None:
        raise asyncio.CancelledError()

    with pytest.raises(asyncio.CancelledError):
        relay.replace("alice", LinkSpec(label="Alice"), on_commit=cancel_commit)

    assert not relay.is_draining("alice")
    # Hourly quota (links_per_hour=1) was refunded both times, so a clean replace succeeds.
    result = relay.replace("alice", LinkSpec(label="Alice"))
    assert isinstance(result, ReplaceResult)
    assert result.created and result.link is not None
    assert relay.links("alice") == [result.link]


def test_replace_auth_validation_error_does_not_leak_reservation_or_teardown():
    relay, _, _ = make_relay(
        max_links=2,
        links_per_hour=2,
        authorize=lambda _req, _link, _op: True,
    )
    existing = relay.create("alice", context=AttemptContext(owner="alice"))
    with pytest.raises(ValueError, match="owner"):
        relay.replace("alice", LinkSpec(context=None))
    assert not existing.closed
    assert relay.links("alice") == [existing]
    # Quota was not consumed by the failed validation.
    res = relay.replace("alice", LinkSpec(context=AttemptContext(owner="alice")))
    assert res.created and res.link is not None


# ---------------------------------------------------------------------------
# Race Class 2: Protecting in-flight saving and post-drain completed links
# ---------------------------------------------------------------------------


def test_replace_preserves_pre_drain_saving_link_and_consumes_zero_quota():
    relay, backend, _ = make_relay(links_per_hour=2)
    old = relay.create("alice")
    win_id = open_window(relay, old)
    backend.states[win_id] = {"state": "saving", "host": "accounts.example.com"}
    relay.advance(old)
    assert old.state == "saving"

    result = relay.replace("alice", LinkSpec())
    assert result.outcome == "saving"
    assert not result.created
    assert result.link is None
    assert result.preserved is old
    assert old in result.still_open
    assert not old.closed
    assert not relay.is_draining("alice")

    # Quota was not consumed: still 1 attempt left out of 2.
    with relay.reserve("alice") as res:
        assert res.active


def test_replace_preserves_link_transitioning_to_saving_during_drain():
    relay, backend, _ = make_relay(links_per_hour=2)
    old = relay.create("alice")
    win_id = open_window(relay, old)

    # Simulate backend transitioning window to saving right as cancel_only close arrives.
    def transition_to_saving(wid: str, cancel_only: bool) -> None:
        if wid == win_id and cancel_only:
            backend.states[wid] = {"state": "saving", "host": "accounts.example.com"}

    backend.on_close = transition_to_saving

    result = relay.replace("alice", LinkSpec())
    assert result.outcome == "saving"
    assert result.preserved is old
    assert old in result.still_open
    assert old.state == "saving"
    assert not relay.is_draining("alice")
    # Quota was refunded/released on refusal.
    with relay.reserve("alice") as res:
        assert res.active


def test_replace_preserves_in_flight_completed_link_post_drain():
    hook_entered = threading.Event()
    release_hook = threading.Event()

    def on_signed_in(_link: Link, _session: dict[str, Any]) -> str:
        hook_entered.set()
        assert release_hook.wait(timeout=5)
        return "verifying"

    relay, backend, _ = make_relay(links_per_hour=2, on_signed_in=on_signed_in)
    old = relay.create("alice")
    win_id = open_window(relay, old)
    backend.states[win_id] = {"state": "signed_in", "host": "accounts.example.com"}
    backend.results[win_id] = {"cookies": [{"name": "sid", "value": "ok"}]}

    # Thread 1 runs advance(old) and pauses inside on_signed_in while holding old.lock.
    adv_thread = threading.Thread(target=relay.advance, args=(old,))
    adv_thread.start()
    assert hook_entered.wait(timeout=5)

    # Thread 2 calls replace() while old is completing in-flight.
    replace_out: list[ReplaceResult] = []
    replace_started = threading.Event()

    def run_replace() -> None:
        replace_started.set()
        replace_out.append(relay.replace("alice", LinkSpec(), completed_states=("verifying", "connected")))

    rep_thread = threading.Thread(target=run_replace)
    rep_thread.start()
    assert replace_started.wait(timeout=5)
    # Wait until replace() has entered draining (blocked on old.lock inside cancel).
    deadline = threading.Event()
    for _ in range(500):
        if relay.is_draining("alice"):
            break
        deadline.wait(0.002)
    assert relay.is_draining("alice")

    # Let on_signed_in complete and set old.state = "verifying".
    release_hook.set()
    adv_thread.join(timeout=5)
    rep_thread.join(timeout=5)

    assert len(replace_out) == 1
    res = replace_out[0]
    assert res.outcome == "completed"
    assert not res.created
    assert res.preserved is old
    assert old.state == "verifying"
    assert not relay.is_draining("alice")

    # A subsequent replace() when old is ALREADY idle+completed succeeds (normal reconnect).
    res2 = relay.replace("alice", LinkSpec(), completed_states=("verifying", "connected"))
    assert res2.created and res2.link is not None
    assert res2.link is not old


def test_replace_returns_closing_when_backend_close_unavailable():
    relay, backend, _ = make_relay(links_per_hour=2)
    old = relay.create("alice")
    open_window(relay, old)

    def fail_close(_wid: str, _cancel_only: bool) -> None:
        raise LoginUnavailable("down")

    backend.on_close = fail_close

    result = relay.replace("alice", LinkSpec())
    assert result.outcome == "closing"
    assert not result.created
    assert old in result.still_open
    assert not relay.is_draining("alice")
    # Quota was not consumed.
    with relay.reserve("alice") as res:
        assert res.active


# ---------------------------------------------------------------------------
# Race Class 3: Stale replace_id mismatch across concurrent replacements
# ---------------------------------------------------------------------------


def test_concurrent_replace_with_same_replace_id_allows_only_one_winner():
    relay, _, _ = make_relay(links_per_hour=10)
    old = relay.create("alice")
    open_window(relay, old)

    workers = 4
    barrier = threading.Barrier(workers)
    results: list[ReplaceResult] = []
    guard = threading.Lock()

    def worker() -> None:
        barrier.wait(timeout=5)
        res = relay.replace("alice", LinkSpec(), replace_id=old.id)
        with guard:
            results.append(res)

    threads = [threading.Thread(target=worker) for _ in range(workers)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=5)

    created = [r for r in results if r.outcome == "created"]
    stale = [r for r in results if r.outcome == "stale_target"]
    assert len(created) == 1
    assert len(stale) == workers - 1
    winner = created[0].link
    assert winner is not None
    assert not winner.closed
    assert relay.links("alice") == [winner]


def test_stale_replace_id_post_drain_does_not_tear_down_newer_link():
    in_close = threading.Event()
    release_close = threading.Event()
    relay, backend, _ = make_relay(links_per_hour=10)
    old = relay.create("alice")
    old_win = open_window(relay, old)

    def slow_close(wid: str, cancel_only: bool) -> None:
        if wid == old_win:
            in_close.set()
            assert release_close.wait(timeout=5)
            backend.states[wid] = {"state": "cancelled"}

    backend.on_close = slow_close

    out: list[ReplaceResult] = []
    t = threading.Thread(target=lambda: out.append(relay.replace("alice", LinkSpec(), replace_id=old.id)))
    t.start()
    assert in_close.wait(timeout=5)

    # While replace(replace_id=old.id) is draining old, a newer link is created for alice.
    newer = relay.create("alice")
    release_close.set()
    t.join(timeout=5)

    assert len(out) == 1
    assert out[0].outcome == "stale_target"
    assert out[0].preserved is newer
    assert not newer.closed
    assert relay.links("alice") == [newer]


# ---------------------------------------------------------------------------
# Race Class 4: Non-blocking snapshot/is_draining + _purged re-insertion guard
# ---------------------------------------------------------------------------


def test_snapshot_and_is_draining_never_block_on_link_lock_during_backend_close():
    in_close = threading.Event()
    release_close = threading.Event()
    relay, backend, _ = make_relay(links_per_hour=10)
    old = relay.create("alice")
    old_win = open_window(relay, old)

    def blocking_close(wid: str, cancel_only: bool) -> None:
        if wid == old_win:
            in_close.set()
            assert release_close.wait(timeout=5)
            backend.states[wid] = {"state": "cancelled"}

    backend.on_close = blocking_close

    out: list[ReplaceResult] = []
    worker = threading.Thread(target=lambda: out.append(relay.replace("alice", LinkSpec())))
    worker.start()
    assert in_close.wait(timeout=5)

    # Confirm old.lock is actually held by the worker thread inside backend.close().
    assert not old.lock.acquire(blocking=False)

    # snapshot() and is_draining() must return immediately without acquiring old.lock.
    assert relay.is_draining("alice") is True
    snap = relay.snapshot("alice")
    assert isinstance(snap, KeySnapshot)
    assert snap.key == "alice"
    assert snap.draining is True
    assert old in snap.links

    release_close.set()
    worker.join(timeout=5)

    assert len(out) == 1 and out[0].created
    assert relay.is_draining("alice") is False
    snap_after = relay.snapshot("alice")
    assert snap_after.draining is False
    assert snap_after.active == (out[0].link,)


def test_drain_and_purge_predicate_before_purge_and_saving_preservation():
    relay, backend, _ = make_relay(links_per_hour=10)
    link_a = relay.create("alice", params={"site": "alpha"})
    open_window(relay, link_a)

    # Non-matching predicate leaves link_a untouched in _links.
    res_other = relay.drain_and_purge("alice", predicate=lambda item: item.params.get("site") == "beta")
    assert res_other == DrainResult()
    assert not link_a.closed and not link_a._purged
    assert relay.snapshot("alice").active == (link_a,)

    # Failing before_purge leaves links unpurged and clears draining.
    def boom() -> None:
        assert relay.is_draining("alice") is True
        raise RuntimeError("persist failed")

    with pytest.raises(RuntimeError, match="persist failed"):
        relay.drain_and_purge("alice", predicate=lambda item: item.params.get("site") == "alpha", before_purge=boom)
    assert relay.is_draining("alice") is False
    assert link_a._purged is False
    assert link_a in relay.snapshot("alice").active

    # Successful before_purge drains and purges alpha.
    hook_calls: list[str] = []
    res = relay.drain_and_purge(
        "alice",
        predicate=lambda item: item.params.get("site") == "alpha",
        before_purge=lambda: hook_calls.append("ran"),
    )
    assert isinstance(res, DrainResult)
    assert hook_calls == ["ran"]
    assert res.purged == (link_a,) and res.drained == (link_a,)
    assert link_a._purged is True
    assert relay.snapshot("alice").links == ()

    # Purging a saving link preserves it instead of purging.
    link_b = relay.create("alice", params={"site": "beta"})
    win_b = open_window(relay, link_b)
    backend.states[win_b] = {"state": "saving", "host": "accounts.example.com"}
    relay.advance(link_b)

    res_saving = relay.drain_and_purge("alice", predicate=lambda item: item.params.get("site") == "beta")
    assert res_saving.purged == ()
    assert res_saving.preserved == (link_b,)
    assert res_saving.still_open == (link_b,)
    assert link_b._purged is False
    assert link_b in relay.snapshot("alice").links


def test_drain_and_purge_prevents_concurrent_retire_and_tick_reinsertion():
    in_retire_close = threading.Event()
    release_retire_close = threading.Event()
    close_calls = 0
    relay, backend, clock = make_relay(links_per_hour=10)
    old = relay.create("alice", params={"site": "alpha"})
    old_win = open_window(relay, old)

    # First close fails with LoginUnavailable so old stays in _retired with closing=True.
    def scripted_close(wid: str, cancel_only: bool) -> None:
        nonlocal close_calls
        if wid != old_win:
            return
        close_calls += 1
        if close_calls == 1:
            # Initial cancel during drain_and_purge succeeds cleanly.
            backend.states[wid] = {"state": "cancelled"}
            return
        # Subsequent concurrent _retire() / tick() sees LoginUnavailable, which
        # would normally re-insert the link into _retired via _track_retired_locked.
        in_retire_close.set()
        assert release_retire_close.wait(timeout=5)
        raise LoginUnavailable("transient")

    backend.on_close = scripted_close

    # Drain and purge old cleanly: old is removed from _links/_retired and marked _purged.
    drain_res = relay.drain_and_purge("alice", predicate=lambda item: item.params.get("site") == "alpha")
    assert drain_res.purged == (old,)
    assert old._purged is True
    assert relay.snapshot("alice").links == ()

    # Now simulate a stale concurrent _retire(old) or tick() thread that had already
    # snapshotted old before purge and tries to re-track it after LoginUnavailable.
    old.window_id = old_win  # simulate pre-purge window reference seen by stale thread
    retire_thread = threading.Thread(target=relay._retire, args=(old,))
    retire_thread.start()
    assert in_retire_close.wait(timeout=5)
    release_retire_close.set()
    retire_thread.join(timeout=5)

    # _purged guard must prevent re-insertion into _retired.
    assert relay.snapshot("alice").retired == ()
    assert old.id not in relay._retired

    # tick() also cleans up and never re-inserts a purged link.
    clock.now += 10.0
    relay.tick()
    assert relay.snapshot("alice").retired == ()
    assert old.id not in relay._retired


# ---------------------------------------------------------------------------
# Surviving links stay open: drains fence links instead of closing them early
# ---------------------------------------------------------------------------


def test_replace_keeps_saving_link_open_and_state_route_stays_reachable():
    backend = ControlledBackend()

    def authorize(request: Any, link: Link, _op: str) -> bool:
        return not link.closed and request.headers.get("x-actor") == (link.context.owner if link.context else "")

    relay, backend, _ = make_relay(backend=backend, links_per_hour=4, authorize=authorize)
    old = relay.create("alice", context=AttemptContext(owner="alice"))
    win_id = open_window(relay, old)

    def transition_to_saving(wid: str, cancel_only: bool) -> None:
        if wid == win_id and cancel_only:
            backend.states[wid] = {"state": "saving", "host": "accounts.example.com"}

    backend.on_close = transition_to_saving

    result = relay.replace("alice", LinkSpec(context=AttemptContext(owner="alice")))
    assert result.outcome == "saving"
    assert result.preserved is old
    assert old.closed is False

    with TestClient(relay.app(), base_url="https://mcp.example.com") as client:
        resp = client.get(f"/{old.id}/state", headers={"x-actor": "alice"})
        assert resp.status_code == 200
        assert resp.json()["state"] == "saving"


def test_replace_closes_stuck_teardown_and_keeps_completed_and_exception_survivors_open():
    # Case A: closing (backend close unavailable) marks the stuck-teardown link closed.
    relay, backend, _ = make_relay(links_per_hour=4)
    old = relay.create("alice")
    open_window(relay, old)
    backend.on_close = lambda _wid, _cancel_only: (_ for _ in ()).throw(LoginUnavailable("down"))

    res_closing = relay.replace("alice", LinkSpec())
    assert res_closing.outcome == "closing"
    assert old in res_closing.still_open
    # A link whose requested teardown is still in flight is dying, so it is closed (as before this change).
    assert old.closed is True

    # Case B: a link completed in flight is preserved and stays open.
    hook_entered = threading.Event()
    release_hook = threading.Event()

    def on_signed_in(_link: Link, _session: dict[str, Any]) -> str:
        hook_entered.set()
        assert release_hook.wait(timeout=5)
        return "connected"

    relay2, backend2, _ = make_relay(links_per_hour=4, on_signed_in=on_signed_in)
    old2 = relay2.create("alice")
    win2 = open_window(relay2, old2)
    backend2.states[win2] = {"state": "signed_in", "host": "accounts.example.com"}
    backend2.results[win2] = {"ok": True}

    adv_thread = threading.Thread(target=relay2.advance, args=(old2,))
    adv_thread.start()
    assert hook_entered.wait(timeout=5)

    out: list[ReplaceResult] = []
    rep_thread = threading.Thread(target=lambda: out.append(relay2.replace("alice", LinkSpec())))
    rep_thread.start()
    waiter = threading.Event()
    for _ in range(500):
        if relay2.is_draining("alice"):
            break
        waiter.wait(0.002)
    assert relay2.is_draining("alice")

    release_hook.set()
    adv_thread.join(timeout=5)
    rep_thread.join(timeout=5)
    assert out[0].outcome == "completed"
    assert out[0].preserved is old2
    assert old2.closed is False

    # Case C: unexpected exception during drain leaves the drained link closed and the unreached link open.
    relay3, backend3, _ = make_relay(links_per_hour=4)
    drained_old = relay3.create("alice")
    win_ok = open_window(relay3, drained_old)
    boom_old = Link(
        id="b" * 32,
        key="alice",
        created=1_000_000.0,
        expires=1_001_200.0,
        url="https://mcp.example.com/connect/" + "b" * 32,
        state="waiting",
        window_id="win-boom",
        closed=False,
    )
    backend3.states["win-boom"] = {"state": "waiting", "host": "accounts.example.com"}

    def selective_boom(wid: str, cancel_only: bool) -> None:
        if wid == win_ok:
            backend3.states[wid] = {"state": "cancelled"}
            return
        raise RuntimeError("unexpected backend crash")

    backend3.on_close = selective_boom

    with pytest.raises(RuntimeError, match="unexpected backend crash"):
        relay3.replace("alice", LinkSpec(), extra_links=(boom_old,))

    assert drained_old.closed is True
    assert boom_old.closed is False
    assert not relay3.is_draining("alice")
    assert relay3._reserved_slots == 0
    assert relay3._reserved_quota == {}


def test_drain_and_purge_keeps_saving_link_open_and_closes_stuck_teardown():
    backend = ControlledBackend()

    def authorize(request: Any, link: Link, _op: str) -> bool:
        return not link.closed and request.headers.get("x-actor") == (link.context.owner if link.context else "")

    relay, backend, _ = make_relay(backend=backend, links_per_hour=6, authorize=authorize)

    # Pre-existing saving link stays closed=False and reachable via state route.
    saving_link = relay.create("alice", context=AttemptContext(owner="alice"))
    win_s = open_window(relay, saving_link)
    backend.states[win_s] = {"state": "saving", "host": "accounts.example.com"}
    relay.advance(saving_link)

    res_saving = relay.drain_and_purge("alice")
    assert res_saving.purged == ()
    assert res_saving.preserved == (saving_link,)
    assert res_saving.still_open == (saving_link,)
    assert saving_link.closed is False

    with TestClient(relay.app(), base_url="https://mcp.example.com") as client:
        resp = client.get(f"/{saving_link.id}/state", headers={"x-actor": "alice"})
        assert resp.status_code == 200
        assert resp.json()["state"] == "saving"

    # Still-open link (backend unavailable) is marked closed but not purged; the drained link is closed and purged.
    relay2, backend2, _ = make_relay(links_per_hour=6)
    stuck = relay2.create("bob")
    win_stuck = open_window(relay2, stuck)
    drainable = Link(
        id="d" * 32,
        key="bob",
        created=1_000_000.0,
        expires=1_001_200.0,
        url="https://mcp.example.com/connect/" + "d" * 32,
        state="ready",
        closed=False,
    )

    def fail_stuck(wid: str, _cancel_only: bool) -> None:
        if wid == win_stuck:
            raise LoginUnavailable("down")

    backend2.on_close = fail_stuck
    res_mixed = relay2.drain_and_purge("bob", extra_links=(drainable,))
    assert res_mixed.purged == (drainable,)
    assert res_mixed.still_open == (stuck,)
    assert drainable.closed is True and drainable._purged is True
    assert stuck.closed is True and stuck._purged is False


# ---------------------------------------------------------------------------
# Item 2: known_completed on Relay.replace()
# ---------------------------------------------------------------------------


def test_replace_known_completed_detects_just_completed_link_without_consuming_quota():
    relay, backend, _ = make_relay(links_per_hour=2, on_signed_in=lambda _l, _s: "connected")
    old = relay.create("alice")
    win_id = open_window(relay, old)

    # Consumer observed old while waiting (so known_completed is empty).
    # Before replace() runs, a poller completes old.
    backend.states[win_id] = {"state": "signed_in", "host": "accounts.example.com"}
    backend.results[win_id] = {"cookies": [{"name": "sid", "value": "ok"}]}
    relay.advance(old)
    assert old.state == "connected" and old.window_id is None

    res = relay.replace("alice", LinkSpec(), known_completed=())
    assert res.outcome == "completed"
    assert not res.created
    assert res.link is None
    assert res.preserved is old
    assert old.closed is False
    assert relay._reserved_slots == 0
    assert relay._reserved_quota == {}
    # Quota was not consumed: still 1 attempt remaining out of links_per_hour=2.
    with relay.reserve("alice") as reservation:
        assert reservation.active

    # Once caller acknowledges old in known_completed, replacement succeeds.
    res2 = relay.replace("alice", LinkSpec(), known_completed=(old.id,))
    assert res2.outcome == "created"
    assert res2.created and res2.link is not None and res2.link is not old
    assert old.closed is True

    # Default known_completed=None preserves previous behaviour (recomputes already_completed).
    relay2, backend2, _ = make_relay(links_per_hour=3, on_signed_in=lambda _l, _s: "connected")
    prior = relay2.create("alice")
    win_p = open_window(relay2, prior)
    backend2.states[win_p] = {"state": "signed_in", "host": "accounts.example.com"}
    backend2.results[win_p] = {"ok": True}
    relay2.advance(prior)
    assert prior.state == "connected"

    res_default = relay2.replace("alice", LinkSpec())
    assert res_default.outcome == "created"
    assert res_default.link is not None and res_default.link is not prior


# ---------------------------------------------------------------------------
# Item 3: Forced drain_and_purge()
# ---------------------------------------------------------------------------


def test_drain_and_purge_force_purges_stuck_link_revokes_token_ignores_late_completion_and_balances_capacity():
    hook_calls: list[str] = []
    relay, backend, clock = make_relay(
        max_links=1,
        links_per_hour=4,
        on_signed_in=lambda link, _session: (hook_calls.append(link.id), "connected")[1],
    )
    stuck = relay.create("alice")
    win_id = open_window(relay, stuck)
    assert stuck.view_token is not None

    backend.on_close = lambda _wid, _cancel_only: (_ for _ in ()).throw(LoginUnavailable("down"))

    # Default force=False leaves stuck link open.
    res_soft = relay.drain_and_purge("alice")
    assert res_soft.purged == ()
    assert res_soft.still_open == (stuck,)
    assert stuck._purged is False

    # force=True closes/revokes/purges stuck link from live and retired tracking.
    res_force = relay.drain_and_purge("alice", force=True)
    assert res_force.purged == (stuck,)
    assert res_force.preserved == ()
    assert res_force.still_open == ()
    assert stuck.closed is True
    assert stuck._purged is True
    assert stuck.view_token is None
    assert stuck.viewer_revoked is True
    assert stuck.window_id is None
    assert stuck.state == "cancelled"
    assert relay.snapshot("alice").active == ()
    assert relay.snapshot("alice").retired == ()
    assert stuck.id not in relay._links
    assert stuck.id not in relay._retired

    # Late completion / poll / retire does nothing and never resurrects stuck.
    backend.states[win_id] = {"state": "signed_in", "host": "accounts.example.com"}
    backend.results[win_id] = {"cookies": [{"name": "sid", "value": "late"}]}
    relay.advance(stuck)
    relay._retire(stuck)
    clock.now += 10.0
    relay.tick()
    assert hook_calls == []
    assert stuck.state == "cancelled"
    assert stuck.id not in relay._links
    assert stuck.id not in relay._retired

    # Capacity and reservation/quota accounting stay balanced (max_links=1 is now free for another key).
    assert relay._reserved_slots == 0
    assert relay._reserved_quota == {}
    with relay.reserve("bob") as res_bob:
        bob_link = relay.create("bob", reservation=res_bob)
        assert bob_link.key == "bob"
    assert relay._reserved_slots == 0
    assert relay._reserved_quota == {}


def test_drain_and_purge_force_still_preserves_saving_link():
    relay, backend, _ = make_relay(links_per_hour=4)
    saving = relay.create("alice")
    win_id = open_window(relay, saving)
    backend.states[win_id] = {"state": "saving", "host": "accounts.example.com"}
    relay.advance(saving)
    assert saving.state == "saving"

    res = relay.drain_and_purge("alice", force=True)
    assert res.purged == ()
    assert res.preserved == (saving,)
    assert res.still_open == (saving,)
    assert saving._purged is False
    assert saving.closed is False
    assert saving in relay.snapshot("alice").links


# ---------------------------------------------------------------------------
# Drain fencing: overlapping calls, concurrent replace, force edge cases,
# known_completed scoping, and live state route during slow drains
# ---------------------------------------------------------------------------


def _wait_until(predicate: Callable[[], bool], *, attempts: int = 1000) -> bool:
    waiter = threading.Event()
    for _ in range(attempts):
        if predicate():
            return True
        waiter.wait(0.002)
    return predicate()


@pytest.mark.parametrize("pair", ["replace+replace", "drain+drain", "replace+drain"])
def test_overlapping_drains_keep_surviving_link_open_with_zero_fences(pair: str):
    in_close = threading.Event()
    release_close = threading.Event()
    call2_entered = threading.Event()
    relay, backend, _ = make_relay(links_per_hour=6)
    old = relay.create("alice")
    win_id = open_window(relay, old)

    def blocking_close(wid: str, cancel_only: bool) -> None:
        if wid == win_id and cancel_only:
            in_close.set()
            assert release_close.wait(timeout=5)
            backend.states[wid] = {"state": "saving", "host": "accounts.example.com"}

    backend.on_close = blocking_close

    out1: list[Any] = []
    out2: list[Any] = []

    def run_call1() -> None:
        if pair.startswith("replace"):
            out1.append(relay.replace("alice", LinkSpec()))
        else:
            out1.append(relay.drain_and_purge("alice"))

    def run_call2() -> None:
        if pair.endswith("replace"):
            out2.append(relay.replace("alice", LinkSpec()))
        else:
            out2.append(
                relay.drain_and_purge(
                    "alice",
                    predicate=lambda _link: (call2_entered.set(), True)[1],
                )
            )

    t1 = threading.Thread(target=run_call1)
    t1.start()
    assert in_close.wait(timeout=5)

    t2 = threading.Thread(target=run_call2)
    t2.start()
    if pair.endswith("drain"):
        assert call2_entered.wait(timeout=5)
    assert _wait_until(lambda: relay._draining.get("alice", 0) == 2 and old._drain_fences == 2)

    release_close.set()
    t1.join(timeout=5)
    t2.join(timeout=5)

    assert len(out1) == 1 and len(out2) == 1
    if pair.startswith("replace"):
        assert out1[0].outcome == "saving" and out1[0].preserved is old
    else:
        assert out1[0].preserved == (old,) and out1[0].purged == ()
    if pair.endswith("replace"):
        assert out2[0].outcome == "saving" and out2[0].preserved is old
    else:
        assert out2[0].preserved == (old,) and out2[0].purged == ()

    assert old.state == "saving"
    assert old.closed is False
    assert old._drain_fences == 0
    assert relay.is_draining("alice") is False


def test_drain_and_purge_does_not_resurrect_link_drained_by_concurrent_replace():
    in_close = threading.Event()
    release_close = threading.Event()
    relay, backend, _ = make_relay(links_per_hour=6)

    slow_link = Link(
        id="s" * 32,
        key="alice",
        created=1_000_000.0,
        expires=1_001_200.0,
        url="https://mcp.example.com/connect/" + "s" * 32,
        state="waiting",
        window_id="win-slow",
        closed=False,
    )
    other_link = Link(
        id="o" * 32,
        key="alice",
        created=1_000_000.0,
        expires=1_001_200.0,
        url="https://mcp.example.com/connect/" + "o" * 32,
        state="ready",
        closed=False,
    )
    backend.states["win-slow"] = {"state": "waiting", "host": "accounts.example.com"}

    def abort_slow(wid: str, _cancel_only: bool) -> None:
        if wid == "win-slow":
            in_close.set()
            assert release_close.wait(timeout=5)
            raise RuntimeError("abort slow drain")

    backend.on_close = abort_slow

    errors: list[BaseException] = []

    def run_drain() -> None:
        try:
            relay.drain_and_purge("alice", extra_links=(slow_link, other_link))
        except BaseException as exc:
            errors.append(exc)

    t = threading.Thread(target=run_drain)
    t.start()
    assert in_close.wait(timeout=5)

    # Concurrent replace() legitimately drains other_link and creates a replacement.
    rep = relay.replace("alice", LinkSpec(), extra_links=(other_link,))
    assert rep.created and rep.link is not None
    assert other_link in rep.drained
    assert other_link.closed is True

    release_close.set()
    t.join(timeout=5)

    assert len(errors) == 1 and isinstance(errors[0], RuntimeError)
    assert other_link.closed is True
    assert other_link._drain_fences == 0
    assert slow_link.closed is False
    assert slow_link._drain_fences == 0
    assert relay.is_draining("alice") is False


def test_drain_and_purge_force_closes_attached_viewer_when_backend_close_unavailable():
    bridge_exited = threading.Event()
    relay, backend, _ = make_relay(links_per_hour=4)

    async def holding_bridge(_wid: str, _token: str, ws: Any) -> None:
        await ws.send_bytes(b"viewer")
        try:
            await asyncio.Future()
        finally:
            bridge_exited.set()

    backend.on_bridge = holding_bridge
    stuck = relay.create("alice")
    open_window(relay, stuck)
    backend.on_close = lambda _wid, _cancel_only: (_ for _ in ()).throw(LoginUnavailable("down"))

    with TestClient(relay.app(), base_url="https://mcp.example.com") as client:
        with client.websocket_connect(f"/{stuck.id}/vnc") as ws:
            assert ws.receive_bytes() == b"viewer"
            res = relay.drain_and_purge("alice", force=True)
            with pytest.raises(WebSocketDisconnect):
                ws.receive_bytes()

    assert bridge_exited.wait(timeout=2)
    assert res.purged == (stuck,)
    assert stuck.closed is True
    assert stuck._purged is True
    assert stuck.view_token is None
    assert stuck.viewer_revoked is True
    assert stuck._drain_fences == 0
    assert relay.is_draining("alice") is False


def test_drain_and_purge_force_preserves_link_turning_saving_during_initial_cancel():
    relay, backend, _ = make_relay(links_per_hour=4)
    old = relay.create("alice")
    win_id = open_window(relay, old)

    def transition_to_saving(wid: str, cancel_only: bool) -> None:
        if wid == win_id and cancel_only:
            backend.states[wid] = {"state": "saving", "host": "accounts.example.com"}

    backend.on_close = transition_to_saving

    res = relay.drain_and_purge("alice", force=True)
    assert res.purged == ()
    assert res.preserved == (old,)
    assert res.still_open == (old,)
    assert old.state == "saving"
    assert old.closed is False
    assert old._purged is False
    assert old._drain_fences == 0
    assert backend.closed == [(win_id, True)]
    assert old in relay.snapshot("alice").links


def test_drain_and_purge_force_before_purge_exception_keeps_state_and_counters_balanced():
    relay, backend, _ = make_relay(links_per_hour=4)
    old = relay.create("alice")
    open_window(relay, old)
    backend.on_close = lambda _wid, _cancel_only: (_ for _ in ()).throw(LoginUnavailable("down"))

    def boom() -> None:
        assert relay.is_draining("alice") is True
        raise RuntimeError("before_purge failed")

    with pytest.raises(RuntimeError, match="before_purge failed"):
        relay.drain_and_purge("alice", force=True, before_purge=boom)

    assert relay.is_draining("alice") is False
    assert old._drain_fences == 0
    assert old._purged is False
    assert old.closed is False
    assert old.window_id is None
    assert old.view_token is None
    assert old.viewer_revoked is True
    assert old in relay.snapshot("alice").active
    assert relay._reserved_slots == 0
    assert relay._reserved_quota == {}


def test_replace_known_completed_ignores_foreign_open_and_replace_id_links():
    # 1. Foreign-key id in known_completed has no effect on alice's completed link.
    relay, backend, _ = make_relay(links_per_hour=4, on_signed_in=lambda _l, _s: "connected")
    bob_link = relay.create("bob")
    bob_win = open_window(relay, bob_link)
    backend.states[bob_win] = {"state": "signed_in", "host": "accounts.example.com"}
    backend.results[bob_win] = {"ok": True}
    relay.advance(bob_link)
    assert bob_link.state == "connected"

    alice_link = relay.create("alice")
    alice_win = open_window(relay, alice_link)
    backend.states[alice_win] = {"state": "signed_in", "host": "accounts.example.com"}
    backend.results[alice_win] = {"ok": True}
    relay.advance(alice_link)
    assert alice_link.state == "connected"

    res_foreign = relay.replace("alice", LinkSpec(), known_completed=(bob_link.id,))
    assert res_foreign.outcome == "completed"
    assert res_foreign.preserved is alice_link
    assert alice_link.closed is False

    # 2. Open link id in known_completed has no effect when that link completes in-flight.
    hook_entered = threading.Event()
    release_hook = threading.Event()

    def slow_signed_in(_link: Link, _session: dict[str, Any]) -> str:
        hook_entered.set()
        assert release_hook.wait(timeout=5)
        return "connected"

    relay2, backend2, _ = make_relay(links_per_hour=4, on_signed_in=slow_signed_in)
    open_link = relay2.create("alice")
    open_win = open_window(relay2, open_link)
    backend2.states[open_win] = {"state": "signed_in", "host": "accounts.example.com"}
    backend2.results[open_win] = {"ok": True}

    adv_t = threading.Thread(target=relay2.advance, args=(open_link,))
    adv_t.start()
    assert hook_entered.wait(timeout=5)

    out_open: list[ReplaceResult] = []
    rep_t = threading.Thread(
        target=lambda: out_open.append(relay2.replace("alice", LinkSpec(), known_completed=(open_link.id,)))
    )
    rep_t.start()
    assert _wait_until(lambda: relay2.is_draining("alice"))

    release_hook.set()
    adv_t.join(timeout=5)
    rep_t.join(timeout=5)
    assert len(out_open) == 1
    assert out_open[0].outcome == "completed"
    assert out_open[0].preserved is open_link
    assert open_link.closed is False

    # 3. replace_id in known_completed has no effect when the target completes in-flight.
    hook_entered2 = threading.Event()
    release_hook2 = threading.Event()

    def slow_signed_in2(_link: Link, _session: dict[str, Any]) -> str:
        hook_entered2.set()
        assert release_hook2.wait(timeout=5)
        return "connected"

    relay3, backend3, _ = make_relay(links_per_hour=4, on_signed_in=slow_signed_in2)
    target = relay3.create("alice")
    target_win = open_window(relay3, target)
    backend3.states[target_win] = {"state": "signed_in", "host": "accounts.example.com"}
    backend3.results[target_win] = {"ok": True}

    adv_t2 = threading.Thread(target=relay3.advance, args=(target,))
    adv_t2.start()
    assert hook_entered2.wait(timeout=5)

    out_target: list[ReplaceResult] = []
    rep_t2 = threading.Thread(
        target=lambda: out_target.append(
            relay3.replace("alice", LinkSpec(), replace_id=target.id, known_completed=(target.id,))
        )
    )
    rep_t2.start()
    assert _wait_until(lambda: relay3.is_draining("alice"))

    release_hook2.set()
    adv_t2.join(timeout=5)
    rep_t2.join(timeout=5)
    assert len(out_target) == 1
    assert out_target[0].outcome == "completed"
    assert out_target[0].preserved is target
    assert target.closed is False


def test_state_route_stays_200_for_completed_link_during_slow_drain_of_sibling():
    in_close = threading.Event()
    release_close = threading.Event()

    def authorize(request: Any, link: Link, _op: str) -> bool:
        return not link.closed and request.headers.get("x-actor") == (link.context.owner if link.context else "")

    relay, backend, _ = make_relay(
        links_per_hour=4,
        authorize=authorize,
        on_signed_in=lambda _l, _s: "connected",
    )
    done_link = relay.create("alice", context=AttemptContext(owner="alice"))
    done_win = open_window(relay, done_link)
    backend.states[done_win] = {"state": "signed_in", "host": "accounts.example.com"}
    backend.results[done_win] = {"ok": True}
    relay.advance(done_link)
    assert done_link.state == "connected"

    slow_sibling = Link(
        id="w" * 32,
        key="alice",
        created=1_000_000.0,
        expires=1_001_200.0,
        url="https://mcp.example.com/connect/" + "w" * 32,
        state="waiting",
        window_id="win-sibling",
        closed=False,
        context=AttemptContext(owner="alice"),
    )
    backend.states["win-sibling"] = {"state": "waiting", "host": "accounts.example.com"}

    def slow_close(wid: str, cancel_only: bool) -> None:
        if wid == "win-sibling" and cancel_only:
            in_close.set()
            assert release_close.wait(timeout=5)
            backend.states[wid] = {"state": "cancelled"}

    backend.on_close = slow_close

    out: list[ReplaceResult] = []
    rep_thread = threading.Thread(
        target=lambda: out.append(
            relay.replace(
                "alice",
                LinkSpec(context=AttemptContext(owner="alice")),
                known_completed=(),
                extra_links=(slow_sibling,),
            )
        )
    )
    rep_thread.start()
    assert in_close.wait(timeout=5)
    try:
        # While slow_sibling is draining, done_link is fenced but NOT closed, so state stays 200.
        assert done_link.closed is False
        assert done_link._drain_fences == 1
        with TestClient(relay.app(), base_url="https://mcp.example.com") as client:
            resp = client.get(f"/{done_link.id}/state", headers={"x-actor": "alice"})
            assert resp.status_code == 200
            assert resp.json()["state"] == "connected"
    finally:
        release_close.set()
        rep_thread.join(timeout=5)

    assert len(out) == 1
    assert out[0].outcome == "completed"
    assert out[0].preserved is done_link
    assert done_link.closed is False
    assert done_link._drain_fences == 0
    assert slow_sibling.closed is True
    assert slow_sibling._drain_fences == 0
    assert relay.is_draining("alice") is False


def test_drain_and_purge_fences_saving_link_that_fails_so_it_cannot_start_a_window_mid_purge():
    in_hook = threading.Event()
    release_hook = threading.Event()
    drain_entered = threading.Event()

    def on_signed_in(_link: Link, _session: Any) -> str:
        in_hook.set()
        assert release_hook.wait(timeout=5)
        return "failed"

    relay, backend, _ = make_relay(links_per_hour=4, on_signed_in=on_signed_in)
    link = relay.create("alice")
    win_id = open_window(relay, link)
    backend.states[win_id] = {"state": "saving", "host": "accounts.example.com"}
    relay.advance(link)
    assert link.state == "saving"
    backend.states[win_id] = {"state": "signed_in", "host": "accounts.example.com"}
    backend.results[win_id] = {"ok": True}

    saver = threading.Thread(target=relay.advance, args=(link,))
    saver.start()
    assert in_hook.wait(timeout=5)
    assert link.state == "saving"

    started_before = len(backend.started)
    during_purge: list[tuple[int, bool]] = []

    def before_purge() -> None:
        # The link has left saving for a retryable state; a retry must not open a window now.
        relay.start(link, "desktop")
        during_purge.append((len(backend.started), link.window_id is None))

    results: list[Any] = []
    drainer = threading.Thread(
        target=lambda: results.append(
            relay.drain_and_purge(
                "alice",
                predicate=lambda _link: (drain_entered.set(), True)[1],
                before_purge=before_purge,
            )
        )
    )
    drainer.start()
    assert drain_entered.wait(timeout=5)
    # The drain fences the saving link, then waits for the hand-over that holds the link lock.
    assert _wait_until(lambda: link._drain_fences == 1)

    release_hook.set()
    saver.join(timeout=5)
    drainer.join(timeout=5)

    assert len(results) == 1
    assert during_purge == [(started_before, True)]
    assert results[0].purged == (link,)
    assert link.closed is True and link._purged is True
    assert link.window_id is None
    assert link._drain_fences == 0
    assert relay.is_draining("alice") is False
    assert relay.snapshot("alice").active == ()
