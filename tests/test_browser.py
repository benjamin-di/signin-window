"""signin_window.browser: the policy files, and harden() on stand-in contexts (scripts/e2e.py drives a real one)."""

from __future__ import annotations

import asyncio
import json

from signin_window import browser


class Page:
    def __init__(self, url: str) -> None:
        self.url = url
        self.main_frame = Frame(self, url)
        self.closed = False
        self.listeners: dict[str, list] = {}

    def on(self, event, handler) -> None:
        self.listeners.setdefault(event, []).append(handler)

    def remove_listener(self, event, handler) -> None:
        self.listeners[event].remove(handler)

    def navigate(self, url: str, frame=None) -> None:
        frame = frame or self.main_frame
        frame.url = url
        for handler in list(self.listeners.get("framenavigated", ())):
            handler(frame)

    def close(self) -> None:
        self.closed = True


class AsyncPage(Page):
    async def close(self) -> None:  # type: ignore[override]
        self.closed = True


class Frame:
    def __init__(self, page: Page, url: str) -> None:
        self.page, self.url = page, url


class Context:
    def __init__(self) -> None:
        self.scripts: list[str] = []
        self.handlers: list = []

    def add_init_script(self, script: str) -> None:
        self.scripts.append(script)

    def on(self, event: str, handler) -> None:
        assert event == "page"
        self.handlers.append(handler)


class AsyncContext(Context):
    async def add_init_script(self, script: str) -> None:  # type: ignore[override]
        self.scripts.append(script)


def test_policy_is_written_and_recognised(tmp_path):
    folders = [tmp_path / "a" / "managed", tmp_path / "b"]
    written = browser.install_policy(folders)
    assert written == [folder / "signin-window.json" for folder in folders]
    assert json.loads(written[0].read_text()) == browser.POLICY
    assert oct(written[0].stat().st_mode & 0o777) == "0o644"
    assert browser.policy_installed(folders)
    assert not browser.policy_installed([tmp_path / "missing"])


def test_a_policy_that_drops_or_weakens_a_setting_is_not_ours(tmp_path):
    for change in ({"PasswordManagerEnabled": True}, {"URLBlocklist": ["file://*"]}, {"DownloadRestrictions": 0}):
        (tmp_path / "signin-window.json").write_text(json.dumps({**browser.POLICY, **change}))
        assert not browser.policy_installed([tmp_path]), change
    wider = {**browser.POLICY, "URLBlocklist": [*browser.POLICY["URLBlocklist"], "https://other.example/*"]}
    (tmp_path / "signin-window.json").write_text(json.dumps({**wider, "MetricsReportingEnabled": False}))
    assert browser.policy_installed([tmp_path])


def test_the_policy_turns_off_saving_passwords_and_leaves_devtools_to_kiosk_mode():
    assert browser.POLICY["PasswordManagerEnabled"] is False
    assert {"file://*", "chrome://*", "devtools://*", "view-source:*"} <= set(browser.POLICY["URLBlocklist"])
    assert "DeveloperToolsAvailability" not in browser.POLICY  # 2 stops Playwright from starting the browser
    assert "--kiosk" in browser.LAUNCH_ARGS


def test_cli_installs_and_checks(tmp_path, capsys):
    assert browser.main(["install-policy", "--dir", str(tmp_path)]) == 0
    assert capsys.readouterr().out.strip() == str(tmp_path / "signin-window.json")


def test_harden_hides_passkeys_and_closes_key_press_tabs():
    context = Context()
    browser.harden_sync(context)
    assert context.scripts == [browser.NO_PASSKEYS] and "PublicKeyCredential" in browser.NO_PASSKEYS
    [opened] = context.handlers

    new_tab = Page("chrome://new-tab-page/")
    opened(new_tab)
    assert new_tab.closed

    blocked = Page("about:blank")  # Ctrl+N with the new tab page blocked: its first page is the error page
    opened(blocked)
    assert not blocked.closed
    blocked.navigate("chrome-error://chromewebdata/")
    assert blocked.closed

    popup = Page("about:blank")  # a site's popup starts on the site, and stays open whatever it shows later
    opened(popup)
    popup.navigate("https://www.example.com/oauth", frame=Frame(popup, ""))  # a frame of it: not its first page
    popup.navigate("https://www.example.com/oauth")
    popup.navigate("chrome-error://chromewebdata/")
    assert not popup.closed and not popup.listeners["framenavigated"]

    on_site = Page("https://www.example.com/")
    opened(on_site)
    assert not on_site.closed


def test_harden_async():
    async def run() -> None:
        context = AsyncContext()
        await browser.harden(context)
        assert context.scripts == [browser.NO_PASSKEYS]
        [opened] = context.handlers
        new_tab, later = AsyncPage("chrome://new-tab-page/"), AsyncPage("about:blank")
        await opened(new_tab)
        await opened(later)
        later.navigate("chrome-error://chromewebdata/")
        await asyncio.sleep(0)
        assert new_tab.closed and later.closed

    asyncio.run(run())


class CDP:
    def __init__(self, contexts: list[str]) -> None:
        self.sent: list[tuple[str, dict | None]] = []
        self.contexts = contexts
        self.handlers: dict[str, list] = {}

    def send(self, method: str, params: dict | None = None) -> dict:
        self.sent.append((method, params))
        if method == "Target.getBrowserContexts":
            return {"browserContextIds": self.contexts}
        if method == "Browser.getWindowForTarget":
            return {"windowId": 7}
        return {}

    def on(self, event: str, handler) -> None:
        self.handlers.setdefault(event, []).append(handler)

    def detach(self) -> None:
        pass


def test_a_new_context_gets_full_screen_windows_and_no_windows_outside_it():
    context, page_session, browser_session = Context(), CDP([]), CDP(["ours"])
    context.pages = [Page("about:blank")]
    context.new_cdp_session = lambda page: page_session
    browser_ = type("Browser", (), {"new_browser_cdp_session": lambda self: browser_session})()
    browser.harden_sync(context, browser_)
    fullscreen = ("Browser.setWindowBounds", {"windowId": 7, "bounds": {"windowState": "fullscreen"}})
    assert page_session.sent == [("Browser.getWindowForTarget", None), fullscreen]
    assert browser_session.sent == [("Target.setDiscoverTargets", {"discover": True})]

    [opened] = context.handlers
    opened(Page("https://www.example.com/popup"))
    assert page_session.sent[-1] == fullscreen

    [created] = browser_session.handlers["Target.targetCreated"]
    created({"targetInfo": {"type": "page", "targetId": "a", "browserContextId": "ours"}})
    created({"targetInfo": {"type": "iframe", "targetId": "b", "browserContextId": "default"}})
    assert ("Target.closeTarget", {"targetId": "a"}) not in browser_session.sent
    assert ("Target.closeTarget", {"targetId": "b"}) not in browser_session.sent
    created({"targetInfo": {"type": "page", "targetId": "c", "browserContextId": "default"}})
    assert browser_session.sent[-1] == ("Target.closeTarget", {"targetId": "c"})
