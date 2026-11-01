"""Optional durable controls for an application's authenticated connection owner.

Applications choose one private root per owner/application, authenticate actions,
and call ``require_active`` before work. This ledger never starts or authorizes
work, changes OAuth grants, or handles browser identity.
"""

from __future__ import annotations

import json
import math
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from .state import PrivateStateError, atomic_private_write, exclusive_lock, read_private_file

_MAX_BYTES = 1024 * 1024


class ConnectionPaused(RuntimeError):
    """The connection owner paused application work without disconnecting."""


@dataclass(frozen=True)
class ConnectionActivity:
    summary: str
    status: str = "Completed"
    url: str | None = None
    occurred_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def __post_init__(self) -> None:
        for value, limit in ((self.summary, 2000), (self.status, 120), (self.occurred_at, 80)):
            if not isinstance(value, str) or not value or len(value) > limit:
                raise ValueError("invalid connection activity text")
        if self.url is not None and (not isinstance(self.url, str) or len(self.url) > 2000):
            raise ValueError("invalid connection activity URL")
        moment = datetime.fromisoformat(self.occurred_at)
        if moment.tzinfo is None or moment.utcoffset() is None:
            raise ValueError("connection activity timestamp must include a timezone")


@dataclass(frozen=True)
class ConnectionStatus:
    paused: bool = False
    # Newest first. Applications report safe summaries, never tokens or raw requests.
    activity: tuple[ConnectionActivity, ...] = ()


class ConnectionControls:
    """Process-safe pause and bounded recent activity, independent of OAuth.

    Missing state starts unpaused. Unreadable/corrupt state raises
    ``PrivateStateError`` so callers cannot mistake it for an active connection.
    The application must still verify consent and entitlement for every run.
    """

    def __init__(self, root: Path, *, max_activity: int = 20, lock_timeout_seconds: float = 5) -> None:
        if type(max_activity) is not int or not 1 <= max_activity <= 40:
            raise ValueError("activity limit must be an integer between 1 and 40")
        if not math.isfinite(lock_timeout_seconds) or lock_timeout_seconds < 0:
            raise ValueError("lock timeout must be nonnegative and finite")
        self.root = Path(root)
        if self.root.is_symlink():
            raise PrivateStateError("connection state directory must not be a symlink")
        self.max_activity = max_activity
        self.lock_timeout_seconds = lock_timeout_seconds

    def _lock(self):
        if self.root.is_symlink():
            raise PrivateStateError("connection state directory must not be a symlink")
        return exclusive_lock(self.root / "controls.lock", timeout_seconds=self.lock_timeout_seconds)

    def _load(self) -> ConnectionStatus:
        try:
            raw = read_private_file(self.root / "controls.json", max_bytes=_MAX_BYTES)
        except FileNotFoundError:
            return ConnectionStatus()
        try:
            value = json.loads(raw)
            if (
                not isinstance(value, dict)
                or set(value) != {"version", "paused", "activity"}
                or type(value["version"]) is not int
                or value["version"] != 1
                or type(value["paused"]) is not bool
                or not isinstance(value["activity"], list)
                or len(value["activity"]) > 40
            ):
                raise ValueError("invalid connection state")
            activity = tuple(ConnectionActivity(**item) for item in value["activity"])
        except (ValueError, TypeError, KeyError) as error:
            raise PrivateStateError("connection state is invalid") from error
        return ConnectionStatus(paused=value["paused"], activity=activity)

    def _write(self, status: ConnectionStatus) -> None:
        value = {"version": 1, "paused": status.paused, "activity": [asdict(item) for item in status.activity]}
        payload = json.dumps(value, ensure_ascii=True).encode()
        if len(payload) > _MAX_BYTES:
            raise PrivateStateError("connection state is oversized")
        atomic_private_write(self.root / "controls.json", payload)

    def snapshot(self) -> ConnectionStatus:
        with self._lock():
            return self._load()

    def set_paused(self, paused: bool) -> None:
        if type(paused) is not bool:
            raise ValueError("paused must be a boolean")
        with self._lock():
            status = self._load()
            self._write(ConnectionStatus(paused=paused, activity=status.activity))

    def require_active(self) -> None:
        """Check immediately before work (and again before sensitive effects)."""
        if self.snapshot().paused:
            raise ConnectionPaused("connection is paused")

    def record_activity(self, activity: ConnectionActivity) -> None:
        if not isinstance(activity, ConnectionActivity):
            raise ValueError("activity must be a ConnectionActivity")
        with self._lock():
            status = self._load()
            self._write(
                ConnectionStatus(
                    paused=status.paused,
                    activity=(activity, *status.activity)[: self.max_activity],
                )
            )
