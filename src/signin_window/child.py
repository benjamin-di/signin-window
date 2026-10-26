"""A sign-in window run as a child process, for sign-in code that cannot run inside the service's event loop: a
synchronous browser library, or another project's own sign-in (as a command).

The child reports progress on stdout, one line each, ``<PREFIX>{json}``; anything else it prints is ignored::

    {"state": "waiting"}                      the sign-in page is up (the live view opens)
    {"host": "accounts.example.com"}          the host the window shows now
    {"state": "saving"}                       revoke control before publication
    {"state": "signed_in", ...the session}    done: the session to hand over
    {"state": "connected"}                    kept mode: the child saved its session
    {"state": "failed", "error": "..."}       it gave up

``emit`` writes such a line from the child. ``run_child`` runs one in its own process group on the window's display,
follows it, and returns the session (the ``signed_in`` line without ``state``); if the window is cancelled or ends
without one, the whole group is stopped and ``WindowFailed`` is raised.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import signal
import subprocess
import sys
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from .service import Window

PREFIX = "SIGNIN "
MAX_LINE = 1024 * 1024  # the last line carries the session
SAVING_ACK = "SIGNIN saving\n"


class WindowFailed(Exception):
    """The child ended without a session."""


def emit(prefix: str = PREFIX, **fields: Any) -> None:
    """Print one progress line (in the child)."""
    print(prefix + json.dumps(fields), flush=True)


def begin_saving() -> None:
    """In a kept child, revoke remote control before publishing its session.

    Blocks until ``run_child(kept=True)`` has moved the window to saving. EOF or
    an unexpected acknowledgement aborts publication. Use the default prefix.
    """
    emit(state="saving")
    if sys.stdin.readline() != SAVING_ACK:
        raise WindowFailed("saving_not_acknowledged")


def parse(line: bytes, prefix: str = PREFIX) -> dict[str, Any] | None:
    """One progress line, or None for anything else the child printed."""
    text = line.decode("utf-8", "replace").strip()
    if not text.startswith(prefix):
        return None
    try:
        message = json.loads(text[len(prefix) :])
    except ValueError:
        return None
    return message if isinstance(message, dict) else None


async def run_child(
    window: Window,
    argv: Sequence[str],
    *,
    env: Mapping[str, str] | None = None,
    prefix: str = PREFIX,
    kept: bool = False,
    stop_seconds: float = 5,
) -> dict[str, Any]:
    """Run a child on the window's display and return its session.

    ``kept=True`` instead requires ``connected`` and exit 0, then finishes the
    window without transferring a session. ``saving`` closes control before
    publication. ``stop_seconds`` gives an application's owned child time to
    restore its profile after SIGTERM; cancellation never releases it early.
    """
    if stop_seconds <= 0:
        raise ValueError("stop_seconds must be positive")
    process = await asyncio.create_subprocess_exec(
        *argv,
        stdin=asyncio.subprocess.PIPE if kept else asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
        env={**(env if env is not None else window.env()), "DISPLAY": window.display},
        start_new_session=True,
        limit=MAX_LINE,
    )
    window.procs.append(ProcessGroup(process.pid))
    session: dict[str, Any] | None = None
    connected = False
    unexpected_session = False
    assert process.stdout is not None
    try:
        while line := await process.stdout.readline():
            message = parse(line, prefix)
            if message is None:
                continue
            if message.get("host"):
                window.at(str(message["host"]))
            state = message.get("state")
            if state == "waiting":
                window.waiting()
            elif state == "saving":
                window.saving()
                if kept:
                    if window.state != "saving" or window.cancelled.is_set():
                        raise WindowFailed("saving_not_acknowledged")
                    assert process.stdin is not None
                    process.stdin.write(SAVING_ACK.encode())
                    await process.stdin.drain()
            elif state == "connected" and kept:
                connected = True
            elif state == "failed":
                window.error = str(message.get("error") or "failed")[:100]
                if kept:
                    unexpected_session = True
            elif state == "signed_in":
                if kept:
                    unexpected_session = True
                else:
                    session = {k: v for k, v in message.items() if k != "state"}
        await process.wait()
    finally:
        if process.stdin is not None:
            process.stdin.close()
        if process.returncode is None:
            with contextlib.suppress(ProcessLookupError, PermissionError):
                os.killpg(process.pid, signal.SIGTERM)
            with contextlib.suppress(Exception, asyncio.CancelledError):
                await asyncio.wait_for(process.wait(), timeout=stop_seconds)  # reap before releasing its profile
    if kept:
        if process.returncode != 0 or not connected or unexpected_session or window.cancelled.is_set():
            raise WindowFailed(window.error or "kept_session_not_confirmed")
        window.finish("connected")
        return {}
    if session is None or process.returncode != 0:
        raise WindowFailed(window.error or f"exit {process.returncode}")
    return session


def running_in_group(pgid: int) -> bool:
    """Whether a process of the group still runs. Zombies do not count: a container whose first process does not
    reap orphans keeps them, though they hold nothing."""
    try:
        os.killpg(pgid, 0)
    except (ProcessLookupError, PermissionError):
        return False
    proc = Path("/proc")
    if not proc.is_dir():
        return True
    for stat in proc.glob("[0-9]*/stat"):
        try:
            text = stat.read_text()
        except OSError:
            continue
        fields = text[text.rfind(")") + 2 :].split()  # state, ppid, pgrp, ... (after "pid (comm) ")
        if len(fields) > 2 and fields[2] == str(pgid) and fields[0] != "Z":
            return True
    return False


def python_module(module: str, *args: str) -> list[str]:
    """``argv`` for ``python -m module args`` with this interpreter."""
    return [sys.executable, "-m", module, *args]


class ProcessGroup:
    """The child's process group, stopped with the window's display (``Windows.stop_display``)."""

    def __init__(self, pid: int) -> None:
        self.pid = pid

    def terminate(self) -> None:
        with contextlib.suppress(ProcessLookupError, PermissionError):
            os.killpg(self.pid, signal.SIGTERM)

    def kill(self) -> None:
        with contextlib.suppress(ProcessLookupError, PermissionError):
            os.killpg(self.pid, signal.SIGKILL)

    def poll(self) -> int | None:
        return None if running_in_group(self.pid) else 0

    def wait(self, timeout: float | None = None) -> int:
        deadline = time.monotonic() + (timeout or 0)
        while self.poll() is None:
            if time.monotonic() >= deadline:
                self.kill()
                raise subprocess.TimeoutExpired("window", timeout or 0)
            time.sleep(0.1)
        return 0
