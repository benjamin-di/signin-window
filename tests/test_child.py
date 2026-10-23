"""A window run as a child process: its progress lines drive the window, its session is returned, and a cancelled
or failed child is stopped with its whole process group."""

from __future__ import annotations

import asyncio
import sys
import textwrap
from pathlib import Path

import pytest

from signin_window.child import PREFIX, WindowFailed, emit, parse, python_module, run_child
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
