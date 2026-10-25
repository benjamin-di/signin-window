"""Explicit browser facade for optional account-maintenance adapters.

Human sign-in windows do not import it. The caller owns the browser context,
profile lease and launch/cleanup policy. Secret application binds an exact
frame origin and document rather than a selector that could follow a redirect.
"""

from __future__ import annotations

import math
import time
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from .auth import PasskeyMode
from .pointer import X11Pointer

_OBSERVATIONAL_EVALUATE_DELAYS_MS = (0, 250, 500, 1000, 1250)


@dataclass(frozen=True, slots=True)
class MouseTarget:
    x: float
    y: float


@dataclass(frozen=True, slots=True)
class ObservedNavigation:
    status: int
    response_url: str
    content_type: str | None


def _browser_origin(url: str) -> str:
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"} or not parts.hostname or parts.username or parts.password:
        return ""
    host = parts.hostname
    if ":" in host:
        host = f"[{host}]"
    port = parts.port
    suffix = "" if port is None or (parts.scheme, port) in {("http", 80), ("https", 443)} else f":{port}"
    return f"{parts.scheme}://{host}{suffix}"


def _navigation_timeout_ms(seconds: float) -> float:
    if not math.isfinite(seconds) or seconds <= 0:
        raise ValueError("navigation timeout must be positive and finite")
    return seconds * 1000


def context_replaced(error: BaseException) -> bool:
    text = str(error).lower()
    return any(
        marker in text
        for marker in ("execution context", "context was destroyed", "frame was detached", "frame detached")
    )


class BrowserSession:
    def __init__(self, context: Any, page: Any, *, display: str | None = None) -> None:
        self.context, self.page, self.display = context, page, display
        self._webauthn_session = None

    def for_page(self, page: Any) -> BrowserSession:
        return type(self)(self.context, page, display=self.display)

    @contextmanager
    def challenge_pointer(self):
        pointer = X11Pointer(self.page, display=self.display)
        try:
            yield pointer
        finally:
            pointer.close()

    @property
    def current_url(self) -> str:
        return self.page.url

    def navigate(self, url: str) -> None:
        self.page.goto(url, wait_until="domcontentloaded")

    def navigate_loaded(self, url: str, *, timeout_seconds: float) -> None:
        """Navigate to a DOM-ready document within a bounded provider timeout."""
        timeout_ms = _navigation_timeout_ms(timeout_seconds)
        self.page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)

    def navigate_committed(self, url: str, *, timeout_seconds: float) -> None:
        """Navigate until the response commits without awaiting a perpetual DOM."""
        timeout_ms = _navigation_timeout_ms(timeout_seconds)
        self.page.goto(url, wait_until="commit", timeout=timeout_ms)

    def navigate_observed(self, url: str, *, timeout_seconds: float) -> ObservedNavigation:
        """Navigate to document commit and retain only observed response facts."""
        timeout_ms = _navigation_timeout_ms(timeout_seconds)

        def observe() -> ObservedNavigation:
            response = self.page.goto(url, wait_until="commit", timeout=timeout_ms)
            if response is None:
                raise RuntimeError("browser navigation produced no response")
            status = getattr(response, "status", None)
            response_url = getattr(response, "url", None)
            if not isinstance(status, int) or isinstance(status, bool):
                raise RuntimeError("browser response status is unavailable")
            if not isinstance(response_url, str) or not response_url:
                raise RuntimeError("browser response URL is unavailable")
            headers = getattr(response, "headers", None)
            content_type: str | None = None
            if isinstance(headers, Mapping):
                raw_content_type = headers.get("content-type")
                if raw_content_type is not None:
                    if not isinstance(raw_content_type, str):
                        raise RuntimeError("browser response content type is invalid")
                    content_type = raw_content_type
            return ObservedNavigation(status=status, response_url=response_url, content_type=content_type)

        observed = observe()
        if not isinstance(observed, ObservedNavigation):
            raise RuntimeError("browser navigation observation is unavailable")
        return observed

    def replace_page(self) -> None:
        """Replace a potentially poisoned page while preserving its context."""

        def replace_current() -> None:
            previous = self.page
            replacement = self.context.new_page()
            self.page = replacement
            with suppress(Exception):
                previous.close()

        replace_current()

    def fill(self, selectors: tuple[str, ...], value: str, *, allowed_origins: frozenset[str] | None = None) -> None:

        def type_value(locator) -> None:
            locator.click()
            locator.fill(value)

        self._with_visible_locator(selectors, type_value, allowed_origins=allowed_origins)

    def fill_all_visible(
        self, selectors: tuple[str, ...], value: str, *, allowed_origins: frozenset[str] | None = None
    ) -> int:
        """Fill every visible match for one combined selector without DOM mutation."""

        def fill_visible() -> int:
            filled = 0
            for candidate in self._visible_locators(selectors, combined=True, allowed_origins=allowed_origins):
                candidate.fill("", timeout=8000)
                candidate.type(value, delay=55, timeout=8000)
                candidate.dispatch_event("change")
                candidate.dispatch_event("blur")
                filled += 1
            if not filled:
                raise RuntimeError("no configured visible control was found")
            return filled

        return int(fill_visible())

    def click(self, selectors: tuple[str, ...]) -> None:
        self._with_visible_locator(selectors, lambda locator: locator.click(timeout=10000, no_wait_after=True))

    def press(self, selectors: tuple[str, ...], key: str) -> None:
        """Send one key to a visible control (e.g. Enter to submit a form field)."""
        self._with_visible_locator(selectors, lambda locator: locator.press(key, timeout=10000))

    def press_page(self, key: str) -> None:
        """Send one page-level key through the semantic action ledger."""
        self.page.keyboard.press(key)

    def mouse_target(self, selectors: tuple[str, ...]) -> MouseTarget:
        """Resolve geometry before provider code claims an authentication submit."""
        locator = self._visible_locator(selectors)
        if locator is None:
            raise RuntimeError("visible control geometry unavailable")
        box = locator.bounding_box()
        if not box or box["width"] <= 0 or box["height"] <= 0:
            raise RuntimeError("visible control geometry unavailable")
        return MouseTarget(x=float(box["x"] + box["width"] / 2), y=float(box["y"] + box["height"] / 2))

    def mouse_click(self, target: MouseTarget) -> None:

        def click_target() -> None:
            self.page.mouse.move(target.x, target.y, steps=4)
            self.page.mouse.click(target.x, target.y)

        click_target()

    def native_click(self, selectors: tuple[str, ...]) -> None:
        """Click one visible control through the selected headed surface."""

        def click_native() -> None:
            locator = self._visible_locator(selectors)
            if locator is None:
                raise RuntimeError("no configured visible control was found")
            box = locator.bounding_box()
            if not box or box["width"] <= 0 or box["height"] <= 0:
                raise RuntimeError("visible control geometry unavailable")
            x = float(box["x"] + box["width"] / 2)
            y = float(box["y"] + box["height"] / 2)
            with self.challenge_pointer() as pointer:
                pointer.move(x, y, steps=8)
                pointer.down()
                try:
                    self.page.wait_for_timeout(60)
                finally:
                    pointer.up()

        click_native()

    def click_matching_text(
        self,
        selectors: tuple[str, ...],
        value: str,
        *,
        excluded_text: tuple[str, ...] = (),
        allowed_origins: frozenset[str] | None = None,
    ) -> bool:
        """Click a visible choice containing a JIT value without returning it."""

        def click_match() -> bool:
            needle = value.strip().casefold()
            if not needle:
                return False
            excluded = tuple(item.casefold() for item in excluded_text)
            for candidate in self._visible_locators(selectors, allowed_origins=allowed_origins):
                label = str(candidate.inner_text()).casefold()
                if needle not in label or any(item in label for item in excluded):
                    continue
                candidate.click(timeout=10000, no_wait_after=True)
                return True
            return False

        return bool(click_match())

    def wait_for_visible(self, selectors: tuple[str, ...], *, timeout_seconds: float = 10) -> bool:
        """Wait for a configured control without reading or returning its text."""
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            if self._visible_locator_while_navigating(selectors) is not None:
                return True
            self.page.wait_for_timeout(250)
        return self._visible_locator_while_navigating(selectors) is not None

    def wait_for_hidden(self, selectors: tuple[str, ...], *, timeout_seconds: float = 10) -> bool:
        """Wait until no configured control remains visible."""
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            if self._visible_locator_while_navigating(selectors) is None:
                return True
            self.page.wait_for_timeout(250)
        return self._visible_locator_while_navigating(selectors) is None

    def click_optional(self, selectors: tuple[str, ...]) -> bool:

        def click_if_present() -> bool:
            try:
                locator = self._visible_locator(selectors)
                if locator is None:
                    return False
                box = locator.bounding_box()
                if not box or box["width"] <= 0 or box["height"] <= 0:
                    return False
                x = float(box["x"] + box["width"] / 2)
                y = float(box["y"] + box["height"] / 2)
                self.page.mouse.move(x, y, steps=4)
                self.page.mouse.click(x, y)
            except Exception:
                return False
            return True

        return bool(click_if_present())

    def suppress_passkeys(self, mode: PasskeyMode) -> bool:
        present = mode is PasskeyMode.EMPTY_PRESENT

        def configure() -> bool:
            self._webauthn_session = self.context.new_cdp_session(self.page)
            self._webauthn_session.send("WebAuthn.enable", {"enableUI": False})
            self._webauthn_session.send(
                "WebAuthn.addVirtualAuthenticator",
                {
                    "options": {
                        "protocol": "ctap2",
                        "transport": "internal",
                        "hasResidentKey": present,
                        "hasUserVerification": True,
                        "automaticPresenceSimulation": present,
                        "isUserVerified": present,
                    }
                },
            )
            return True

        return bool(configure())

    def evaluate(self, expression: str) -> object:
        for attempt, delay_ms in enumerate(_OBSERVATIONAL_EVALUATE_DELAYS_MS, start=1):
            if delay_ms:
                self.page.wait_for_timeout(delay_ms)
            try:
                return self.page.evaluate(expression)
            except Exception as error:
                if attempt == len(_OBSERVATIONAL_EVALUATE_DELAYS_MS) or not context_replaced(error):
                    raise
        raise AssertionError("evaluate retry loop exhausted")

    def add_init_script(self, script: str) -> None:
        """Install one provider-owned script before its next document loads."""
        self.page.add_init_script(script)

    def cookies(self) -> list[dict[str, object]]:
        return self.context.cookies()

    def replace_cookies(self, cookies: list[dict[str, object]]) -> None:
        """Replace the retained context's portable cookie set."""

        def replace_all() -> None:
            self.context.clear_cookies()
            if cookies:
                self.context.add_cookies(cookies)

        replace_all()

    def clear_storage(self) -> None:
        """Clear page-local storage without returning its contents."""
        self.page.evaluate(
            """() => {
                try { localStorage.clear(); } catch (_) {}
                try { sessionStorage.clear(); } catch (_) {}
            }"""
        )

    def dispatch_challenge_action(self, dispatch: Callable[[], Any]) -> Any:
        """Record one challenge mutation before handing control to its mechanic."""
        return dispatch()

    def user_agent(self) -> str:
        value = self.evaluate("() => navigator.userAgent")
        if not isinstance(value, str) or not value.strip():
            raise RuntimeError("browser user agent is unavailable")
        return value.strip()

    def wait(self, seconds: float) -> None:
        self.page.wait_for_timeout(seconds * 1000)

    def _with_visible_locator(
        self,
        selectors: tuple[str, ...],
        action: Callable[[Any], None],
        *,
        allowed_origins: frozenset[str] | None = None,
    ) -> None:
        locator = self._visible_locator(selectors, allowed_origins=allowed_origins)
        if locator is None:
            raise RuntimeError("no configured visible control was found")
        action(locator)

    def _visible_locator(
        self, selectors: tuple[str, ...], *, allowed_origins: frozenset[str] | None = None
    ) -> Any | None:
        return next(self._visible_locators(selectors, allowed_origins=allowed_origins), None)

    def _visible_locators(
        self, selectors: tuple[str, ...], *, combined: bool = False, allowed_origins: frozenset[str] | None = None
    ) -> Iterator[Any]:
        roots = getattr(self.page, "frames", None) or (self.page,)
        for root in roots:
            if allowed_origins is not None and _browser_origin(getattr(root, "url", "")) not in allowed_origins:
                continue
            selected = (", ".join(selectors),) if combined else selectors
            for selector in selected:
                locator = root.locator(selector)
                for index in range(locator.count()):
                    candidate = locator.nth(index)
                    if not candidate.is_visible():
                        continue
                    if allowed_origins is None:
                        yield candidate
                        continue
                    handle = candidate.element_handle()
                    if handle is None:
                        continue
                    if _browser_origin(getattr(root, "url", "")) in allowed_origins:
                        yield handle

    def _visible_locator_while_navigating(self, selectors: tuple[str, ...]) -> Any | None:
        """Treat a transient document replacement as not-yet-visible."""
        try:
            return self._visible_locator(selectors)
        except Exception as error:
            if not context_replaced(error):
                raise
            return None
