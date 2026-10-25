"""Bounded headed Chromium lifetime for explicitly authorized maintenance.

The application must hold its durable profile lease across this context. It
owns navigation policy and verification. Importing this module starts nothing.
"""

from __future__ import annotations

import os
import select
import subprocess
import threading
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from ..browser import browser_environment as browser_environment
from .browser import BrowserSession
from .profiles import OwnedBrowserProcess, ProfileError, ProfileFailure, prepare_profile


@contextmanager
def virtual_display(*, xvfb: str = "Xvfb") -> Iterator[str]:
    """Let Xvfb allocate a free display; expose no TCP or remote-view listener."""
    reader, writer = os.pipe()
    process = None
    try:
        process = subprocess.Popen(
            [xvfb, "-displayfd", str(writer), "-screen", "0", "1280x900x24", "-nolisten", "tcp"],
            pass_fds=(writer,),
            env=browser_environment(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        os.close(writer)
        writer = -1
        if not select.select([reader], [], [], 10)[0]:
            raise RuntimeError("virtual display did not become ready")
        raw = os.read(reader, 64).strip()
        if not raw.isdigit() or len(raw) > 5 or int(raw) > 65535 or process.poll() is not None:
            raise RuntimeError("virtual display did not become ready")
        yield f":{int(raw)}"
    finally:
        os.close(reader)
        if writer >= 0:
            os.close(writer)
        if process is not None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


@contextmanager
def open_browser(
    profile: Path,
    *,
    display: str,
    locale: str | None = None,
    timezone_id: str | None = None,
    accept_language: str | None = None,
    args: tuple[str, ...] = (),
    recovery_directory: str = ".signin-singleton-recovery",
    environment: Mapping[str, str] | None = None,
) -> Iterator[BrowserSession]:
    """Open one exclusively leased profile and reap only its owned browser.

    The ten-second shutdown watchdog uses a pidfd bound to this invocation's
    Chromium. It never guesses that a free file lease makes a foreign browser
    safe to kill. Profiles, cookies and account state are never deleted.
    """
    from patchright.sync_api import sync_playwright

    profile = profile.expanduser()
    if profile.is_symlink():
        raise ProfileError(ProfileFailure.PROFILE_INVALID)
    profile.mkdir(mode=0o700, parents=True, exist_ok=True)
    profile = profile.resolve()
    if not display.startswith(":") or not display[1:].isdigit():
        raise ValueError("a local virtual display is required")
    prepare_profile(profile, recovery_directory=recovery_directory)
    manager, context, owned = None, None, None
    primary_failure = False
    try:
        manager = sync_playwright().start()
        context = manager.chromium.launch_persistent_context(
            str(profile),
            headless=False,
            no_viewport=True,
            locale=locale,
            timezone_id=timezone_id,
            extra_http_headers={"Accept-Language": accept_language} if accept_language else None,
            args=list(args) or None,
            env={**browser_environment(environment), "DISPLAY": display},
        )
        owned = OwnedBrowserProcess.capture(profile)
        if owned is None:
            raise ProfileError(ProfileFailure.PROFILE_OWNER_UNVERIFIED)
        page = context.pages[0] if context.pages else context.new_page()
        yield BrowserSession(context, page, display=display)
    except BaseException:
        primary_failure = True
        raise
    finally:
        close_owned_browser(context, manager, owned, primary_failure=primary_failure)


def close_owned_browser(
    context: Any, manager: Any, owned: OwnedBrowserProcess | None, *, primary_failure: bool = False
) -> None:
    """Close caller-owned resources, with a pidfd watchdog for Chromium only.

    This is also usable by a human runner that launched and hardened its own
    browser. It performs no page action or credential access.
    """
    errors: list[BaseException] = []

    def stop_owned():
        if owned is not None:
            try:
                owned.stop_if_alive()
            except Exception as error:
                errors.append(error)

    watchdog = threading.Timer(10, stop_owned) if owned is not None else None
    if watchdog is not None:
        watchdog.daemon = True
        watchdog.start()
    try:
        for resource, operation in ((context, "close"), (manager, "stop")):
            if resource is not None:
                try:
                    getattr(resource, operation)()
                except Exception as error:
                    errors.append(error)
    finally:
        if watchdog is not None:
            watchdog.cancel()
            watchdog.join(timeout=5)
        if owned is not None:
            try:
                stop_owned()
                if owned.forced or not owned.exited():
                    errors.append(ProfileError(ProfileFailure.BROWSER_CLEANUP_FAILED))
            finally:
                owned.close()
    if errors and not primary_failure:
        raise ProfileError(ProfileFailure.BROWSER_CLEANUP_FAILED)
