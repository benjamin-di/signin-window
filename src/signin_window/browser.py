"""Chromium for a sign-in window: the person signs in on the site and can do nothing else in that browser.

Three parts, for a runner that starts Chromium with Playwright (or a fork such as patchright):

* ``LAUNCH_ARGS``: kiosk mode. No address bar, tabs, menus or window frame, so there is nowhere to type an address,
  and every window fills the virtual display (which has no window manager to place it). Kiosk mode also turns
  DevTools off.
* ``POLICY``: Chromium's managed policy, which the image installs as root (``python -m signin_window.browser
  install-policy``) and a service checks with ``policy_installed()`` before it opens a window. Chromium does not
  offer to save passwords or fill addresses and cards, and opens no local files, downloads, file dialogs, printing,
  browser sign-in or sync; its own pages (new tab, history, settings) and ``file:``, ``data:``, ``view-source:``
  addresses show "blocked". It leaves DevTools *availability* alone: Playwright drives the browser through the same
  protocol, and ``DeveloperToolsAvailability: 2`` stops it from starting at all.
* ``harden(context)`` (``harden_sync`` for Playwright's sync API): closes the tab or window a key press opens (Ctrl+T,
  Ctrl+N) so it cannot cover the sign-in. Kiosk mode reaches only the windows of the browser's own profile (a
  persistent context): for ``browser.new_context()`` pass ``browser`` too, and each window is made full screen (which
  kiosk mode keeps it) and windows the person opens outside the context are closed.

None of it changes what a page sees of the browser. Passkeys in particular stay: a site may offer one, and it cannot
work here (no authenticator is near the server), so the person picks the site's other way. Removing WebAuthn from
the pages would hide those offers, but a Chrome without it contradicts itself, and sign-in pages are where bot checks
look hardest. The coherent alternative, DevTools' WebAuthn environment without an authenticator, makes
``isConditionalMediationAvailable()`` answer false, and sites then show a "Sign in with a passkey" button instead.

Keep a window on the site with request routing as well (``signin_window.hosts``): a link on the page can still lead
elsewhere, and kiosk mode only removes the ways to type an address.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
from collections.abc import Iterable
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

LAUNCH_ARGS = ("--kiosk",)

POLICY: dict[str, Any] = {
    "URLBlocklist": [
        "file://*",
        "chrome://*",
        "chrome-untrusted://*",
        "chrome-extension://*",
        "devtools://*",
        "view-source:*",
        "filesystem:*",
        "data:*",
        "blob:*",
        "javascript://*",
        "ftp://*",
    ],
    "PasswordManagerEnabled": False,
    "AutofillAddressEnabled": False,
    "AutofillCreditCardEnabled": False,
    "ImportSavedPasswords": False,
    "AllowFileSelectionDialogs": False,
    "DownloadRestrictions": 3,
    "PrintingEnabled": False,
    "BrowserSignin": 0,
    "SyncDisabled": True,
    "IncognitoModeAvailability": 1,
    "BrowserGuestModeEnabled": False,
    "BrowserAddPersonEnabled": False,
    "EditBookmarksEnabled": False,
}
# Where Chromium reads managed policies on Linux: Chrome for Testing (Playwright's and patchright's "chromium"),
# Google Chrome, and distribution Chromium builds.
POLICY_DIRS = (
    Path("/etc/opt/chrome_for_testing/policies/managed"),
    Path("/etc/opt/chrome/policies/managed"),
    Path("/etc/chromium/policies/managed"),
)
POLICY_NAME = "signin-window.json"

# Where a tab or window opened by a key press lands: the new tab page, or the error page when that is blocked.
_BROWSER_PAGES = ("chrome://", "chrome-error://", "chrome-untrusted://")


def install_policy(dirs: Iterable[Path] = POLICY_DIRS, name: str = POLICY_NAME) -> list[Path]:
    """Write ``POLICY`` into each policy folder (as root, in the image). Returns the files written."""
    written = []
    for folder in dirs:
        folder.mkdir(mode=0o755, parents=True, exist_ok=True)
        path = folder / name
        path.write_text(json.dumps(POLICY, indent=2) + "\n", encoding="utf-8")
        os.chmod(path, 0o644)
        written.append(path)
    return written


def policy_installed(dirs: Iterable[Path] = POLICY_DIRS, name: str = POLICY_NAME) -> bool:
    """Whether ``POLICY`` (or a policy that contains it) is installed where Chromium reads it."""
    for folder in dirs:
        try:
            installed = json.loads((folder / name).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(installed, dict) and _contains(installed, POLICY):
            return True
    return False


def _contains(installed: dict[str, Any], wanted: dict[str, Any]) -> bool:
    for key, value in wanted.items():
        if isinstance(value, list):
            if not set(value) <= set(installed.get(key) or ()):
                return False
        elif installed.get(key) != value:
            return False
    return True


async def harden(context: Any, browser: Any = None) -> None:
    """Close the tabs and windows a key press opens in ``context`` (async API).

    ``browser``: the browser ``context`` came from, when it is a ``browser.new_context()`` rather than a persistent
    context: its windows are made full screen and windows outside it are closed (the browser holds no other context).
    """

    async def opened(page: Any) -> None:
        if _first_url_is_browser_page(page):
            await page.close()
        elif browser is not None:
            await _fullscreen(context, page)

    context.on("page", opened)
    if browser is None:
        return
    for page in context.pages:
        await _fullscreen(context, page)
    cdp = await browser.new_browser_cdp_session()

    async def created(event: dict[str, Any]) -> None:
        target = event.get("targetInfo") or {}
        if target.get("type") == "page":
            contexts = (await cdp.send("Target.getBrowserContexts")).get("browserContextIds") or []
            if target.get("browserContextId") not in contexts:  # the browser's own profile: Ctrl+N's window
                await cdp.send("Target.closeTarget", {"targetId": target["targetId"]})

    cdp.on("Target.targetCreated", created)
    await cdp.send("Target.setDiscoverTargets", {"discover": True})


def harden_sync(context: Any, browser: Any = None) -> None:
    """``harden`` for Playwright's sync API."""

    def opened(page: Any) -> None:
        if _first_url_is_browser_page(page):
            page.close()
        elif browser is not None:
            _fullscreen_sync(context, page)

    context.on("page", opened)
    if browser is None:
        return
    for page in context.pages:
        _fullscreen_sync(context, page)
    cdp = browser.new_browser_cdp_session()

    def created(event: dict[str, Any]) -> None:
        target = event.get("targetInfo") or {}
        if target.get("type") == "page":
            contexts = cdp.send("Target.getBrowserContexts").get("browserContextIds") or []
            if target.get("browserContextId") not in contexts:
                cdp.send("Target.closeTarget", {"targetId": target["targetId"]})

    cdp.on("Target.targetCreated", created)
    cdp.send("Target.setDiscoverTargets", {"discover": True})


_FULLSCREEN = {"windowState": "fullscreen"}


async def _fullscreen(context: Any, page: Any) -> None:
    try:
        cdp = await context.new_cdp_session(page)
        window = await cdp.send("Browser.getWindowForTarget")
        await cdp.send("Browser.setWindowBounds", {"windowId": window["windowId"], "bounds": _FULLSCREEN})
        await cdp.detach()
    except Exception:  # a page closed meanwhile; the window keeps its size
        log.warning("could not make a sign-in window full screen", exc_info=True)


def _fullscreen_sync(context: Any, page: Any) -> None:
    try:
        cdp = context.new_cdp_session(page)
        window = cdp.send("Browser.getWindowForTarget")
        cdp.send("Browser.setWindowBounds", {"windowId": window["windowId"], "bounds": _FULLSCREEN})
        cdp.detach()
    except Exception:
        log.warning("could not make a sign-in window full screen", exc_info=True)


def _first_url_is_browser_page(page: Any) -> bool:
    """True when a new page already shows a browser page; otherwise watch its first navigation and close it then.

    Pages a site opens (popups) and pages the runner opens start on the site, so only a key press's tab or window
    is closed, and never a page that is already in use.
    """
    url = page.url or ""
    if url.startswith(_BROWSER_PAGES):
        return True
    if url not in ("", "about:blank"):
        return False

    def first(frame: Any) -> None:
        url = frame.url or ""
        if frame is not page.main_frame or url in ("", "about:blank"):
            return  # a new tab commits about:blank before the page it opens
        page.remove_listener("framenavigated", first)
        if url.startswith(_BROWSER_PAGES):
            closing = page.close()
            if asyncio.iscoroutine(closing):
                asyncio.ensure_future(closing)  # noqa: RUF006 - the page's own close; nothing waits for it

    page.on("framenavigated", first)
    return False


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m signin_window.browser", description=__doc__.split("\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    install = sub.add_parser("install-policy", help="write the managed Chromium policy (run as root, in the image)")
    install.add_argument("--dir", action="append", type=Path, help="policy folder (repeatable; default: all known)")
    sub.add_parser("check-policy", help="exit 0 when the policy is installed")
    args = parser.parse_args(argv)
    if args.command == "install-policy":
        for path in install_policy(args.dir or POLICY_DIRS):
            print(path)
        return 0
    return 0 if policy_installed() else 1


if __name__ == "__main__":
    raise SystemExit(main())
