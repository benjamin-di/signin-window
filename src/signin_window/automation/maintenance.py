"""Durable holds and publication watermarks with application-supplied models.

The caller owns reason enums, schema, permitted targets and cooldown policy.
This store owns locking, compare-and-clear and atomic persistence. Nothing here
reads credentials, selects a site, or schedules browser work.
"""

from __future__ import annotations

import json
import math
from collections.abc import Callable, Iterator, Sequence
from contextlib import ExitStack, contextmanager
from datetime import datetime, timedelta
from pathlib import Path
from uuid import uuid4

from ..state import PrivateStateError, atomic_private_write, exclusive_lock, read_private_file


class MaintenanceStateStore:
    """Preserve the caller's JSON schema and increasing publication generation."""

    def __init__(
        self,
        root: Path,
        *,
        state_type,
        hold_type,
        cooldown_type,
        valid_keys: frozenset[str],
        block_cooldowns: Sequence[timedelta],
        utc_now: Callable[[], datetime],
        error_type: type[Exception] = PrivateStateError,
        label: str = "maintenance state",
        lock_timeout_seconds: float = 5,
    ) -> None:
        if not valid_keys or any(not key or "/" in key or key in {".", ".."} for key in valid_keys):
            raise ValueError("explicit maintenance keys are required")
        if not block_cooldowns or any(
            not math.isfinite(t.total_seconds()) or t <= timedelta(0) for t in block_cooldowns
        ):
            raise ValueError("positive finite cooldowns are required")
        self.root = Path(root)
        self._state_type, self._hold_type, self._cooldown_type = state_type, hold_type, cooldown_type
        self._keys, self._cooldowns = valid_keys, tuple(block_cooldowns)
        self._utc_now, self._error_type, self._label = utc_now, error_type, label
        self._lock_timeout_seconds = lock_timeout_seconds

    def _error(self, message: str) -> Exception:
        return self._error_type(f"{self._label} {message}")

    def load(self, target: str):
        with self._locked(target):
            return self._load(target)

    def record_hold(self, target: str, reason):
        hold = self._hold_type(hold_id=f"hold-{uuid4().hex[:16]}", reason=reason, recorded_at=self._utc_now())
        with self._locked(target):
            self._write(target, self._load(target).model_copy(update={"hold": hold}))
        return hold

    def replace_hold(self, target: str, hold_id: str, reason):
        """Keep the id only if the provisional hold is still current."""
        with self._locked(target):
            state = self._load(target)
            if state.hold is not None and state.hold.hold_id == hold_id:
                hold = state.hold.model_copy(update={"reason": reason})
            else:
                hold = self._hold_type(hold_id=f"hold-{uuid4().hex[:16]}", reason=reason, recorded_at=self._utc_now())
            self._write(target, state.model_copy(update={"hold": hold}))
        return hold

    def clear_hold(self, target: str, hold_id: str) -> bool:
        with self._locked(target):
            state = self._load(target)
            if state.hold is None or state.hold.hold_id != hold_id:
                return False
            self._write(target, state.model_copy(update={"hold": None}))
        return True

    def record_block(self, target: str, reason):
        with self._locked(target):
            state = self._load(target)
            count = state.consecutive_blocks + 1
            delay = self._cooldowns[min(count, len(self._cooldowns)) - 1]
            cooldown = self._cooldown_type(reason=reason, until=self._utc_now() + delay)
            self._write(target, state.model_copy(update={"cooldown": cooldown, "consecutive_blocks": count}))
        return cooldown

    def record_publish(self, target: str, generation: int) -> None:
        with self._locked(target):
            state = self._load(target)
            if type(generation) is not int or generation <= state.last_generation:
                raise self._error("generation must increase")
            self._write(
                target,
                state.model_copy(
                    update={
                        "last_generation": generation,
                        "last_published_at": self._utc_now(),
                        "cooldown": None,
                        "consecutive_blocks": 0,
                    }
                ),
            )

    @contextmanager
    def _locked(self, target: str) -> Iterator[None]:
        with ExitStack() as stack:
            try:
                stack.enter_context(
                    exclusive_lock(self._path(target).with_suffix(".lock"), timeout_seconds=self._lock_timeout_seconds)
                )
            except PrivateStateError as error:
                raise self._error("is unavailable") from error
            yield

    def _path(self, target: str) -> Path:
        if target not in self._keys:
            raise self._error("key is invalid")
        return self.root / f"{target}.json"

    def _load(self, target: str):
        path = self._path(target)
        if path.is_symlink():
            raise self._error("must be a regular file")
        try:
            raw = read_private_file(path, max_bytes=64 * 1024)
        except FileNotFoundError:
            return self._state_type()
        except OSError as error:
            raise self._error("is unreadable") from error
        try:
            return self._state_type.model_validate(json.loads(raw))
        except (ValueError, RecursionError) as error:
            raise self._error("is malformed") from error

    def _write(self, target: str, state) -> None:
        try:
            atomic_private_write(self._path(target), json.dumps(state.model_dump(mode="json"), sort_keys=True).encode())
        except PrivateStateError as error:
            raise self._error("write failed") from error
