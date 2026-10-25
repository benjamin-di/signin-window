"""Durability and concurrency across independent maintenance processes."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from multiprocessing import get_context

import pytest

from signin_window.sessions import AttemptBudget, SessionStillDead, WarmFirst, refresh_due
from signin_window.state import PrivateStateError

NOW = datetime(2030, 1, 2, tzinfo=UTC)


class SignedOut(Exception):
    pass


def test_warm_session_needs_no_sign_in():
    def forbidden():
        pytest.fail("warm sessions never sign in")

    flow = WarmFirst(lambda: "verified", forbidden, signed_out=SignedOut)
    assert flow.run() == "verified"
    assert not flow.reauthenticated
    with pytest.raises(RuntimeError):
        flow.run()


@pytest.mark.parametrize("failure", [TimeoutError, ValueError])
def test_inconclusive_failures_do_not_attempt_sign_in(failure):
    def refresh():
        raise failure("synthetic failure")

    def forbidden():
        pytest.fail("only positive signed-out evidence permits sign-in")

    with pytest.raises(failure):
        WarmFirst(refresh, forbidden, signed_out=SignedOut).run()


def test_one_failed_sign_in_never_repeats():
    calls = []

    def refresh():
        raise SignedOut()

    flow = WarmFirst(refresh, lambda: calls.append("sign-in"), signed_out=SignedOut)
    with pytest.raises(SessionStillDead):
        flow.run()
    assert calls == ["sign-in"]
    assert flow.reauthenticated


def _reserve(root, ready, start, results):
    budget = AttemptBudget(root, utc_now=lambda: NOW)
    ready.put(True)
    start.wait(5)
    results.put(budget.reserve("example", limit=1))


def test_two_processes_share_one_reservation(tmp_path):
    ctx = get_context("spawn")
    ready, results, start = ctx.Queue(), ctx.Queue(), ctx.Event()
    children = [ctx.Process(target=_reserve, args=(tmp_path, ready, start, results)) for _ in range(2)]
    for child in children:
        child.start()
    try:
        assert ready.get(timeout=10) and ready.get(timeout=10)
        start.set()
        assert sorted([results.get(timeout=10), results.get(timeout=10)]) == [False, True]
    finally:
        for child in children:
            child.join(timeout=10)
            if child.is_alive():
                child.terminate()
                child.join(timeout=5)
            assert child.exitcode == 0


def test_adopts_existing_ledger_and_preserves_interrupted_attempt(tmp_path):
    path = tmp_path / "example.json"
    path.write_text(json.dumps({"attempts": [(NOW - timedelta(hours=1)).isoformat()]}))
    budget = AttemptBudget(tmp_path, utc_now=lambda: NOW)
    before = path.read_bytes()
    assert not budget.reserve("example", limit=1)
    assert path.read_bytes() == before
    assert budget.next_attempt_at("example", limit=1) == NOW + timedelta(hours=23)
    assert budget.reserve("example", limit=2)
    # The caller may crash without reporting completion; another process still
    # cannot repeat the operation.
    assert not AttemptBudget(tmp_path, utc_now=lambda: NOW).reserve("example", limit=2)
    assert path.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize("payload", [b"broken", b"[]", b'{"attempts":null}', b'{"attempts":["2030-01-01"]}'])
def test_corrupt_ledger_never_refunds_an_attempt(tmp_path, payload):
    path = tmp_path / "example.json"
    path.write_bytes(payload)
    with pytest.raises(PrivateStateError):
        AttemptBudget(tmp_path, utc_now=lambda: NOW).reserve("example", limit=1)
    assert path.read_bytes() == payload


def test_symlink_cannot_redirect_budget_writes(tmp_path):
    target = tmp_path / "target"
    target.write_text("private fixture")
    (tmp_path / "example.json").symlink_to(target)
    with pytest.raises(PrivateStateError):
        AttemptBudget(tmp_path, utc_now=lambda: NOW).reserve("example", limit=1)
    assert target.read_text() == "private fixture"


def test_nonregular_budget_fails_without_blocking(tmp_path):
    import os

    os.mkfifo(tmp_path / "example.json")
    with pytest.raises(PrivateStateError):
        AttemptBudget(tmp_path).reserve("example", limit=1)


@pytest.mark.parametrize("limit", [0, -1, True, 1.5])
def test_invalid_budget_limit_is_rejected_before_state_changes(tmp_path, limit):
    with pytest.raises(ValueError):
        AttemptBudget(tmp_path, utc_now=lambda: NOW).reserve("example", limit=limit)
    assert not list(tmp_path.iterdir())


def test_refresh_request_respects_failure_spacing():
    assert not refresh_due(0, now=10, interval=100, failed_at=8, retry_after=20, requested=True)
    assert refresh_due(0, now=30, interval=100, failed_at=8, retry_after=20, requested=True, request_gap=25)
    assert not refresh_due(25, now=30, interval=100, requested=True, request_gap=25)


def test_unverified_session_waits_after_failure_then_is_due():
    assert not refresh_due(0, now=10, interval=100, failed_at=8, retry_after=20, unverified=True)
    assert refresh_due(0, now=30, interval=100, failed_at=8, retry_after=20, unverified=True)


def test_pure_helpers_do_not_require_posix_locks():
    import subprocess
    import sys

    program = """
import importlib.abc
import sys
class NoPosixLock(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == 'fcntl':
            raise ImportError('POSIX locks deliberately unavailable')
sys.meta_path.insert(0, NoPosixLock())
from signin_window.sessions import WarmFirst, refresh_due
assert refresh_due(None, now=0, interval=60)
assert WarmFirst(lambda: 'warm', lambda: None, signed_out=LookupError).run() == 'warm'
assert 'fcntl' not in sys.modules
"""
    subprocess.run([sys.executable, "-c", program], check=True)
