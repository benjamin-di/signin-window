"""Session-maintenance primitives, independent of a site's session format.

Applications own account verification, schedules, holds and session publication.
The primitives here share durable attempt accounting and refresh scheduling.
Nothing opens a browser, reads credentials or starts a background worker.
"""

from __future__ import annotations

import json
import math
import os
import re
import stat
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Generic, TypeVar

from .state import PrivateStateError, atomic_private_write, exclusive_lock

_KEY = re.compile(r"[a-z][a-z0-9_-]{0,31}\Z")
_MAX_BYTES = 64 * 1024
_T = TypeVar("_T")


class SessionStillDead(RuntimeError):
    """A completed sign-in was followed by positive signed-out evidence."""


class WarmFirst(Generic[_T]):
    """Reuse an existing session before one caller-authorized sign-in.

    Only the caller's explicit signed-out exception permits sign-in. Network,
    challenge, account and verification errors pass through without doing so.
    The caller owns credential budgets, holds, leases and access verification.
    """

    def __init__(
        self,
        refresh: Callable[[], _T],
        sign_in: Callable[[], None],
        *,
        signed_out: type[Exception],
    ) -> None:
        self._refresh, self._sign_in = refresh, sign_in
        self._signed_out = signed_out
        self._ran = False
        self.reauthenticated = False

    def run(self) -> _T:
        if self._ran:
            raise RuntimeError("a maintenance attempt can run only once")
        self._ran = True
        try:
            return self._refresh()
        except self._signed_out:
            self._sign_in()
            self.reauthenticated = True
        try:
            return self._refresh()
        except self._signed_out:
            raise SessionStillDead("session remained signed out") from None


class AttemptBudget:
    """Reserve an attempt durably before any credential or challenge action.

    A separate root scopes one tenant/account. Keys name sites or operations.
    The default rolling window and ``{"attempts": [ISO timestamps]}`` file
    format permit adoption of existing ledgers without refunding spent work.
    A failed operation remains counted, including a process killed mid-flight.
    """

    def __init__(
        self,
        root: Path,
        *,
        utc_now: Callable[[], datetime] | None = None,
        window: timedelta = timedelta(days=1),
        lock_timeout_seconds: float = 5,
        error_type: type[Exception] = PrivateStateError,
        label: str = "attempt budget",
    ) -> None:
        if not math.isfinite(window.total_seconds()) or window <= timedelta(0):
            raise ValueError("budget window must be positive and finite")
        if not math.isfinite(lock_timeout_seconds) or lock_timeout_seconds < 0:
            raise ValueError("budget lock timeout must be nonnegative and finite")
        self.root = Path(root)
        self._utc_now = utc_now or (lambda: datetime.now(UTC))
        self._window = window
        self._lock_timeout_seconds = lock_timeout_seconds
        self._error_type, self._label = error_type, label

    def _error(self, message: str) -> Exception:
        return self._error_type(f"{self._label} {message}")

    def _now(self) -> datetime:
        now = self._utc_now()
        if now.tzinfo is None or now.utcoffset() is None:
            raise self._error("clock must be timezone-aware")
        return now

    @staticmethod
    def _limit(limit: int) -> None:
        if type(limit) is not int or not 1 <= limit <= 10000:
            raise ValueError("attempt limit must be an integer between 1 and 10000")

    def attempts_today(self, key: str) -> int:
        """Compatibility name: count attempts within the configured window."""
        with self._locked(key):
            recorded = self._load(key)
        horizon = self._now() - self._window
        return sum(moment > horizon for moment in recorded)

    def next_attempt_at(self, key: str, *, limit: int) -> datetime | None:
        self._limit(limit)
        with self._locked(key):
            recorded = self._load(key)
        horizon = self._now() - self._window
        retained = sorted(moment for moment in recorded if moment > horizon)
        return None if len(retained) < limit else retained[len(retained) - limit] + self._window

    def reserve(self, key: str, *, limit: int) -> bool:
        self._limit(limit)
        with self._locked(key):
            now = self._now()
            recorded = self._load(key)
            retained = [moment for moment in recorded if moment > now - self._window]
            if len(retained) >= limit:
                if retained != recorded:
                    self._write(key, retained)
                return False
            retained.append(now)
            self._write(key, retained)
            return True

    @contextmanager
    def _locked(self, key: str) -> Iterator[None]:
        try:
            with exclusive_lock(self._lock_path(key), timeout_seconds=self._lock_timeout_seconds):
                yield
        except PrivateStateError as error:
            raise self._error("is unavailable") from error

    def _path(self, key: str) -> Path:
        if not isinstance(key, str) or _KEY.fullmatch(key) is None:
            raise self._error("key is invalid")
        return self.root / f"{key}.json"

    def _lock_path(self, key: str) -> Path:
        return self._path(key).with_suffix(".lock")

    def _load(self, key: str) -> list[datetime]:
        path = self._path(key)
        try:
            descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
            with os.fdopen(descriptor, "rb") as stream:
                metadata = os.fstat(stream.fileno())
                if not stat.S_ISREG(metadata.st_mode):
                    raise self._error("must be a regular file")
                if metadata.st_size > _MAX_BYTES:
                    raise self._error("is oversized")
                raw = stream.read(_MAX_BYTES + 1)
        except FileNotFoundError:
            return []
        except OSError as error:
            raise self._error("is unreadable") from error
        if len(raw) > _MAX_BYTES:
            raise self._error("is oversized")
        try:
            payload = json.loads(raw)
            if not isinstance(payload, dict) or set(payload) != {"attempts"}:
                raise ValueError("invalid budget")
            if not isinstance(payload["attempts"], list) or len(payload["attempts"]) > 10000:
                raise ValueError("invalid budget")
            recorded = [datetime.fromisoformat(value) for value in payload["attempts"]]
            if any(moment.tzinfo is None or moment.utcoffset() is None for moment in recorded):
                raise ValueError("naive timestamp")
        except (ValueError, TypeError, KeyError, OverflowError) as error:
            raise self._error("is malformed") from error
        return recorded

    def _write(self, key: str, recorded: list[datetime]) -> None:
        payload = json.dumps({"attempts": [moment.isoformat() for moment in sorted(recorded)]}, sort_keys=True)
        try:
            atomic_private_write(self._path(key), payload.encode())
        except PrivateStateError as error:
            raise self._error("write failed") from error


def refresh_due(
    last_checked: float | None,
    *,
    now: float,
    interval: float,
    failed_at: float | None = None,
    retry_after: float | None = None,
    requested: bool = False,
    request_gap: float = 0,
    unverified: bool = False,
) -> bool:
    """A bounded refresh schedule, with failure spacing and early requests.

    A request never bypasses failure spacing. Applications select the interval
    and decide whether an account is signed in or held before asking this.
    """
    values = (now, interval, request_gap, *(v for v in (last_checked, failed_at, retry_after) if v is not None))
    if any(not isinstance(v, (int, float)) or isinstance(v, bool) or not math.isfinite(v) for v in values):
        raise ValueError("refresh times must be finite numbers")
    if interval <= 0 or request_gap < 0 or (retry_after is not None and retry_after < 0):
        raise ValueError("refresh intervals are invalid")
    if failed_at is not None and retry_after is not None and now - failed_at < min(interval, retry_after):
        return False
    if last_checked is None or unverified:
        return True
    age = now - last_checked
    return age >= interval or (requested and age >= request_gap)
