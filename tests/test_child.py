"""A window run as a child process: its progress lines drive the window, its session is returned, and a cancelled
or failed child is stopped with its whole process group."""

from __future__ import annotations

import asyncio
import io
import sys
import textwrap
from pathlib import Path

import pytest

from signin_window.child import PREFIX, WindowFailed, begin_saving, emit, parse, python_module, run_child
from signin_window.service import Window


def window() -> Window:
    return Window("w" * 24, "desktop", 3, 0.0, 60.0)


def child(tmp_path, body: str) -> list[str]:
    script = tmp_path / "child.py"
    script.write_text(textwrap.dedent(body))
    return [sys.executable, str(script)]


def test_progress_lines_drive_the_window_and_the_session_is_returned(tmp_path):
    argv = child(
        tmp_path,
        f"""
        import json, os
        print("noise from a library")
        print({PREFIX!r} + json.dumps({{"host": "accounts.example.com"}}), flush=True)
        print({PREFIX!r} + json.dumps({{"state": "waiting"}}), flush=True)
        print({PREFIX!r} + "not json")
        print({PREFIX!r} + json.dumps({{"state": "signed_in", "cookies": [], "display": os.environ["DISPLAY"]}}))
        """,
    )
    w = window()
    session = asyncio.run(run_child(w, argv))
    assert session == {"cookies": [], "display": ":93"}
    assert w.state == "waiting" and w.host == "accounts.example.com"


def test_a_child_that_gives_up_fails_with_its_error(tmp_path):
    argv = child(
        tmp_path,
        f"""
        import json, sys
        print({PREFIX!r} + json.dumps({{"state": "failed", "error": "credentials_in_environment"}}), flush=True)
        sys.exit(2)
        """,
    )
    with pytest.raises(WindowFailed, match="credentials_in_environment"):
        asyncio.run(run_child(window(), argv))


def test_a_session_from_a_child_that_then_fails_is_not_returned(tmp_path):
    argv = child(
        tmp_path,
        f"""
        import json, sys
        print({PREFIX!r} + json.dumps({{"state": "signed_in", "cookies": []}}), flush=True)
        sys.exit(1)
        """,
    )
    with pytest.raises(WindowFailed):
        asyncio.run(run_child(window(), argv))


def test_a_cancelled_window_stops_the_childs_whole_group(tmp_path):
    pids = tmp_path / "pids"
    argv = child(
        tmp_path,
        f"""
        import subprocess, sys, time
        grandchild = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
        open({str(pids)!r}, "w").write(str(grandchild.pid))
        time.sleep(60)
        """,
    )
    w = window()

    async def scenario():
        task = asyncio.create_task(run_child(w, argv))
        for _ in range(200):
            if pids.exists() and pids.read_text():
                break
            await asyncio.sleep(0.02)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(scenario())
    for proc in w.procs:  # what Windows.stop_display does
        proc.terminate()
        proc.wait(timeout=5)
    assert not running(int(pids.read_text()))


def running(pid: int) -> bool:
    try:
        return Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0] != "Z"
    except (OSError, IndexError):
        return False


def test_emit_and_parse_round_trip(capsys):
    emit(state="waiting")
    emit("OTHER ", host="example.com")
    out = capsys.readouterr().out.splitlines()
    assert parse(out[0].encode()) == {"state": "waiting"}
    assert parse(out[1].encode()) is None and parse(out[1].encode(), "OTHER ") == {"host": "example.com"}
    assert parse(b"SIGNIN [1, 2]") is None


def test_python_module_runs_this_interpreter():
    assert python_module("site_login.window", "example.de") == [sys.executable, "-m", "site_login.window", "example.de"]


def test_a_child_cannot_begin_publication_after_the_parent_pipe_closes(monkeypatch, capsys):
    monkeypatch.setattr(sys, "stdin", io.StringIO(""))
    with pytest.raises(WindowFailed, match="saving_not_acknowledged"):
        begin_saving()
    assert parse(capsys.readouterr().out.encode()) == {"state": "saving"}


def test_a_kept_child_closes_control_before_publication_and_never_transfers_a_session(tmp_path):
    argv = child(
        tmp_path,
        f"""
        import json
        print({PREFIX!r} + json.dumps({{"state": "waiting", "host": "accounts.example.com"}}), flush=True)
        print({PREFIX!r} + json.dumps({{"state": "saving"}}), flush=True)
        print({PREFIX!r} + json.dumps({{"state": "connected"}}), flush=True)
    """,
    )
    w = window()
    assert asyncio.run(run_child(w, argv, kept=True)) == {}
    assert w.state == "saving" and w.result is None
    assert w._outcome == ("connected", None)


@pytest.mark.parametrize("exit_code, state", [(1, "connected"), (0, "waiting"), (0, "signed_in")])
def test_a_kept_child_requires_explicit_completion_and_successful_exit(tmp_path, exit_code, state):
    argv = child(
        tmp_path,
        f"""
        import json, sys
        print({PREFIX!r} + json.dumps({{"state": {state!r}}}), flush=True)
        sys.exit({exit_code})
    """,
    )
    w = window()
    with pytest.raises(WindowFailed):
        asyncio.run(run_child(w, argv, kept=True))
    assert w._outcome is None and w.result is None


@pytest.mark.parametrize("state", ["signed_in", "failed"])
def test_a_kept_child_cannot_override_a_rejected_record_with_connected(tmp_path, state):
    argv = child(
        tmp_path,
        f"""
        import json
        print({PREFIX!r} + json.dumps({{"state": {state!r}, "cookies": ["synthetic"]}}), flush=True)
        print({PREFIX!r} + json.dumps({{"state": "connected"}}), flush=True)
    """,
    )
    with pytest.raises(WindowFailed):
        asyncio.run(run_child(window(), argv, kept=True))


def test_kept_publication_waits_for_the_parent_to_revoke_control(tmp_path):
    revoked = tmp_path / "revoked"
    argv = child(
        tmp_path,
        f"""
        import json, pathlib, sys
        print({PREFIX!r} + json.dumps({{"state": "saving"}}), flush=True)
        assert sys.stdin.readline() == "SIGNIN saving\\n"
        assert pathlib.Path({str(revoked)!r}).read_text() == "saving"
        print({PREFIX!r} + json.dumps({{"state": "connected"}}), flush=True)
    """,
    )

    class ObservedWindow(Window):
        def saving(self):
            super().saving()
            revoked.write_text(self.state)

    w = ObservedWindow("w" * 24, "desktop", 3, 0.0, 60.0)
    assert asyncio.run(run_child(w, argv, kept=True)) == {}


def test_cancellation_waits_for_the_owned_child_to_restore_before_returning(tmp_path):
    ready, restored = tmp_path / "ready", tmp_path / "restored"
    argv = child(
        tmp_path,
        f"""
        import pathlib, signal, time
        def restore(*args):
            time.sleep(0.2)
            pathlib.Path({str(restored)!r}).write_text("restored")
            raise SystemExit(0)
        signal.signal(signal.SIGTERM, restore)
        pathlib.Path({str(ready)!r}).touch()
        time.sleep(60)
    """,
    )

    async def scenario():
        task = asyncio.create_task(run_child(window(), argv, kept=True, stop_seconds=2))
        for _ in range(200):
            if ready.exists():
                break
            await asyncio.sleep(0.02)
        assert ready.exists()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert restored.read_text() == "restored"

    asyncio.run(scenario())
