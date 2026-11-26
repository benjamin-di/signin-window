"""Deterministic concurrency and lifecycle tests for Relay.reserve, replace, drain_and_purge, and snapshot."""

from __future__ import annotations

import asyncio
import threading
from collections.abc import Callable
from typing import Any

import pytest

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
