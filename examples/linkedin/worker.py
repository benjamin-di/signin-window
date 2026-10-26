"""Owned login child: upstream controls profiles, browser launch and publication."""

from __future__ import annotations

import argparse
import asyncio
import json
import signal
from pathlib import Path

from linkedin_mcp_server.config import AppConfig, BrowserConfig, ServerConfig, set_config
from linkedin_mcp_server.login_viewer import LoginViewer
from linkedin_mcp_server.session_state import load_source_state, portable_cookie_path
from linkedin_mcp_server.setup import interactive_login

from signin_window.child import begin_saving, emit


class HostedView:
    """Retain upstream's Openbox lifetime; the host owns VNC on this display."""

    def __init__(self):
        self.viewer = LoginViewer()

    def start_window_manager(self):
        self.viewer.start_window_manager()

    def start_remote_control(self):
        return None  # the parent's relay supplies the expiring address

    def stop_remote_control(self):
        pass  # the saving progress event revokes control before export

    def stop_window_manager(self):
        self.viewer.stop_window_manager()


async def run(config_file: Path, *, synthetic: bool, fail_export: bool = False):
    data = json.loads(config_file.read_text())
    config = AppConfig(
        browser=BrowserConfig(**data["browser"]),
        server=ServerConfig(**data["server"]),
        is_interactive=data["is_interactive"],
    )
    config.validate()
    set_config(config)
    if synthetic:
        from synthetic import install

        install(fail_export=fail_export)
    closed = False

    def observe(progress):
        nonlocal closed
        if progress.state == "closed":
            closed = progress.close_confirmed is True
        elif progress.state == "saving":
            begin_saving()
        else:
            emit(state=progress.state, host=progress.host)

    task = asyncio.current_task()
    loop = asyncio.get_running_loop()
    interrupted = False

    def cancel_once():
        nonlocal interrupted
        if not interrupted:
            interrupted = True
            task.cancel()

    for signum in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(signum, cancel_once)
    try:
        profile = Path(config.browser.user_data_dir)
        succeeded = await interactive_login(profile, login_viewer=True, viewer_factory=HostedView, observer=observe)
        if (
            not succeeded
            or not closed
            or load_source_state(profile) is None
            or not portable_cookie_path(profile).is_file()
        ):
            emit(state="failed", error="session_not_confirmed")
            return 1
        emit(state="connected")
        return 0
    except asyncio.CancelledError:
        emit(state="failed", error="cancelled")
        return 130
    except Exception as exc:
        emit(state="failed", error=type(exc).__name__)
        return 1
    finally:
        for signum in (signal.SIGTERM, signal.SIGINT):
            loop.remove_signal_handler(signum)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--synthetic", action="store_true")
    parser.add_argument("--fail-export", action="store_true")
    args = parser.parse_args()
    raise SystemExit(asyncio.run(run(args.config, synthetic=args.synthetic, fail_export=args.fail_export)))


if __name__ == "__main__":
    main()
