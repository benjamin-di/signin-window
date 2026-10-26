"""Optional Amazon adapter. Requires the three prepared upstream extension points.

The application owns browser login, verification and publication. signin-window
owns only the interactive display and the link. No credentials are configured.
"""

from __future__ import annotations

import copy
import json
import os
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit

from amazonorders.contrib.browser.playwright import PlaywrightBrowserLogin
from amazonorders.exception import AmazonOrdersError
from amazonorders_mcp.session import SavedSession

from signin_window.browser import LAUNCH_ARGS, harden_sync
from signin_window.hosts import top_level
from signin_window.service import Window


class HumanLogin(PlaywrightBrowserLogin):
    def __init__(self, session, window: Window, synthetic: bool):
        super().__init__(session)
        self.window, self.synthetic = window, synthetic

    def launch_env(self):
        # Child-only settings: never mutate this process's DISPLAY or leak service credentials.
        allowed = ("PATH", "LD_LIBRARY_PATH", "LANG", "LC_ALL", "TZ", "XKB_CONFIG_ROOT", "XDG_RUNTIME_DIR")
        return self.window.env({key: os.environ[key] for key in allowed if key in os.environ})

    def launch_args(self):
        return [*LAUNCH_ARGS, "--window-position=0,0", "--no-first-run"]

    def new_context(self, browser):
        context = super().new_context(browser)
        harden_sync(context, browser)
        own = urlsplit(self.config.constants.BASE_URL).hostname
        resources = (
            "media-amazon.com",
            "ssl-images-amazon.com",
            "images-amazon.com",
            "awswaf.com",
            "cloudfront.net",
            "a2z.com",
        )

        def route(request_route):
            request = request_route.request
            parsed = urlsplit(request.url)
            hosts = (own,) if self.synthetic else (own, "amazon.com", *(resources if not top_level(request) else ()))
            if parsed.scheme in (("http",) if self.synthetic else ("https",)) and any(
                parsed.hostname == host or (parsed.hostname or "").endswith("." + host) for host in hosts
            ):
                request_route.continue_()
            else:
                request_route.abort()

        context.route("**/*", route)
        return context

    def on_sign_in_page(self, context, page):
        self.window.waiting(urlsplit(page.url).hostname or "")

    def wait_for_sign_in(self, context, page, timeout):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline and not self.window.cancelled.is_set():
            if self.is_signed_in(context.cookies()):
                self.window.saving()  # close control before verification and publication
                return
            page.wait_for_timeout(100)
        raise AmazonOrdersError("The interactive sign-in ended before completion.")


class AmazonConnect:
    def __init__(self, sessions: SavedSession, *, synthetic: bool = False):
        self.sessions, self.synthetic = sessions, synthetic
        self.guard = threading.Lock()
        self.generations: dict[str, int] = {}
        self.relay = None

    def create(self, site=None):
        site = self.sessions.site(site)
        with self.guard:
            generation = self.generations.get(site, 0) + 1
            link = self.relay.create(site, params={"site": site, "key": site, "generation": generation})
            self.generations[site] = generation
        return {"url": link.url, "expires_at": link.expires_at}

    def run(self, window: Window):
        site = window.params["site"]

        def login(current):
            stage = copy.deepcopy(current.config)
            stage.cookie_jar_path = str(Path(window.temp_profile("amazon-stage-")) / "cookies.json")
            if stage.cookie_jar_path == current.config.cookie_jar_path:
                raise AmazonOrdersError("An environment override prevents staging.")
            stage.update_config("request_timeout", 10, save=False)
            # Public Amazon APIs, including its own browser selection and verification.
            from amazonorders.session import AmazonSession

            candidate = AmazonSession(config=stage, io=current.io)
            try:
                HumanLogin(candidate, window, self.synthetic).login(max(1, int(window.deadline - time.monotonic())))
                cookies = json.loads(Path(stage.cookie_jar_path).read_text())
                with self.guard:
                    if window.cancelled.is_set() or self.generations.get(site) != window.params["generation"]:
                        raise AmazonOrdersError("This sign-in was superseded.")
                    current.import_cookies(cookies)
                    window.finish("connected")
            finally:
                candidate.session.close()

        self.sessions.sign_in_with(login, site)
