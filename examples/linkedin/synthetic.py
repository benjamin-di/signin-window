"""A test-only provider surface. Every context request is fulfilled or aborted."""

from urllib.parse import urlsplit

from linkedin_mcp_server import setup
from linkedin_mcp_server.core import BrowserManager

SIGNIN = """<!doctype html><title>Synthetic sign-in</title>
<button autofocus onclick="document.cookie='li_at=synthetic-cookie; path=/; SameSite=Lax';
 location.href='/feed/'">Complete synthetic sign-in</button>"""
FEED = "<!doctype html><title>Synthetic feed</title><h1>Synthetic connected account</h1>"


def install(*, fail_export=False):
    class SyntheticBrowser(BrowserManager):
        async def start(self):
            await super().start()

            async def route(request_route):
                parts = urlsplit(request_route.request.url)
                if (
                    parts.scheme == "https"
                    and parts.hostname == "www.linkedin.com"
                    and parts.path in ("/login", "/feed/")
                ):
                    await request_route.fulfill(
                        content_type="text/html", body=SIGNIN if parts.path == "/login" else FEED
                    )
                else:
                    await request_route.abort()

            await self.context.route("**/*", route)

        async def export_cookies(self, cookie_path=None):
            if fail_export:
                return False
            return await super().export_cookies(cookie_path)

    # Only the synthetic launcher installs this fixture seam. Browser launch,
    # the manual-login detector, profile lease, rotation and restoration stay real.
    setup.BrowserManager = SyntheticBrowser
