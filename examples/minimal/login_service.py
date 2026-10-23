"""A login service for one site: Chromium on the site's sign-in page, on a virtual display, shown to the person
through noVNC until the site sets its session cookie; then the session is handed over to the server once.

Run it beside your server on a private network (Dockerfile beside this file), with ``SIGNIN_TOKEN`` (32+ random
characters) shared with the server. Change ``SITE``, ``SIGN_IN_URL`` and ``SESSION_COOKIE`` for your site.
"""

from __future__ import annotations

import asyncio
import os

import uvicorn
from playwright.async_api import async_playwright

from signin_window.browser import LAUNCH_ARGS, harden, policy_installed
from signin_window.hosts import allowed, host_matches, host_resolver_rules, proxy_hosts
from signin_window.service import Window, Windows, build_app

SITE = "example.com"
SIGN_IN_URL = "https://www.example.com/signin"
SESSION_COOKIE = "session"
#: The hosts the window may show and load from: the site's own (add its sign-in and CDN hosts).
HOSTS = (SITE,)


async def sign_in(window: Window) -> dict | None:
    if not policy_installed():  # the image installs it (Dockerfile); without it, no window opens
        raise RuntimeError("the managed Chromium policy is not installed")
    width, height = window.size
    async with async_playwright() as playwright:
        context = await playwright.chromium.launch_persistent_context(
            window.temp_profile(),
            headless=False,
            env=window.env(),
            no_viewport=True,
            accept_downloads=False,
            args=[
                f"--host-resolver-rules={host_resolver_rules(HOSTS, proxy_hosts())}",
                "--window-position=0,0",
                f"--window-size={width},{height}",
                "--no-first-run",
                *LAUNCH_ARGS,  # kiosk: no address bar, tabs or menus
            ],
        )
        await harden(context)  # no passkey offers; Ctrl+T and Ctrl+N open nothing

        async def keep_on_site(route):
            if allowed(route.request.url, HOSTS):
                await route.continue_()
            else:
                await route.abort("blockedbyclient")

        await context.route("**/*", keep_on_site)
        page = context.pages[0] if context.pages else await context.new_page()
        await page.goto(SIGN_IN_URL)
        window.waiting(SITE)
        page.on("framenavigated", lambda frame: frame.parent_frame is None and window.at(frame.url.split("/")[2]))
        while not window.cancelled.is_set():  # the person signs in; nothing here touches the page
            cookies = await context.cookies()
            if any(cookie["name"] == SESSION_COOKIE for cookie in cookies):
                return {"cookies": [c for c in cookies if host_matches(c["domain"].lstrip("."), SITE)]}
            await asyncio.sleep(1)
    return None


def main() -> None:
    windows = Windows(sign_in, slots=1, minutes=15)
    app = build_app(
        windows,
        token=os.environ["SIGNIN_TOKEN"],
        novnc_dir=os.environ.get("NOVNC_DIR", "/opt/novnc"),
        title=f"Sign in to {SITE}",
    )
    uvicorn.run(app, host="0.0.0.0", port=8080, log_level="warning")


if __name__ == "__main__":
    main()
