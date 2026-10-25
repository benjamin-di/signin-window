"""A real profile, native display, exact-origin secret application and cleanup."""

import shutil
import time

import pytest

pytest.importorskip("patchright.sync_api")
if not shutil.which("Xvfb"):
    pytest.skip("native automation needs Xvfb", allow_module_level=True)

from signin_window.automation.runtime import open_browser, virtual_display


def test_profile_reopens_after_owned_browser_cleanup(tmp_path):
    profile = tmp_path / "profile"
    with virtual_display() as display:
        with open_browser(profile, display=display) as browser:
            browser.page.route(
                "https://auth.example.com/**",
                lambda route: route.fulfill(
                    body=(
                        "<input id='username'><input id='password' type='password'>"
                        "<button id='submit' onclick=\"this.textContent='accepted'\">Continue</button>"
                    ),
                    content_type="text/html",
                ),
            )
            browser.navigate_loaded("https://auth.example.com/start", timeout_seconds=10)
            browser.fill(("#username",), "synthetic-user", allowed_origins=frozenset({"https://auth.example.com"}))
            assert browser.page.locator("#username").input_value() == "synthetic-user"
            with pytest.raises(RuntimeError, match="visible control"):
                browser.fill(
                    ("#password",), "synthetic-password", allowed_origins=frozenset({"https://other.example.com"})
                )
            assert browser.page.locator("#password").input_value() == ""
            browser.native_click(("#submit",))
            assert browser.page.locator("#submit").inner_text() == "accepted"
            browser.context.add_cookies(
                [
                    {
                        "name": "synthetic",
                        "value": "kept",
                        "url": "https://auth.example.com",
                        "expires": time.time() + 3600,
                    }
                ]
            )
        assert not (profile / "SingletonLock").exists()
        with open_browser(profile, display=display) as browser:
            assert any(cookie["name"] == "synthetic" and cookie["value"] == "kept" for cookie in browser.cookies())
        assert not (profile / "SingletonLock").exists()
