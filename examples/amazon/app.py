"""An optional remote-human-login host composed with unmodified upstream tools."""

from __future__ import annotations

import argparse
import contextlib
import os
from pathlib import Path

import anyio
import uvicorn
from adapter import AmazonConnect
from amazonorders.conf import AmazonOrdersConfig
from amazonorders_mcp.server import BearerTokenMiddleware, create_server
from amazonorders_mcp.session import SavedSession
from starlette.applications import Starlette
from starlette.routing import Mount
from synthetic import Provider

from signin_window.browser import policy_installed
from signin_window.client import LocalBackend
from signin_window.page import PageText
from signin_window.relay import Relay
from signin_window.service import Windows


def make_app(config, *, public_url, token, novnc_dir, synthetic=False, windows_factory=Windows):
    if len(token) < 32:
        raise ValueError("a token of at least 32 characters is required")
    if not synthetic and not policy_installed():
        raise ValueError("the browser's managed policy is required for actual sign-in")
    if any(name.startswith("AMAZON_") for name in os.environ):
        raise ValueError("configure this prototype through its config, without AMAZON_ environment overrides")
    if any(getattr(config, name, None) for name in ("username", "password", "otp_secret_key")):
        raise ValueError("human sign-in requires a config without stored credentials")
    sessions = SavedSession(config)
    connect = AmazonConnect(sessions, synthetic=synthetic)
    server = create_server(
        sessions,
        additional_instructions="For remote human sign-in use amazon_connect; give its "
        "link to the account holder, then use check_session after they finish.",
    )

    @server.tool()
    async def amazon_connect(site: str | None = None) -> dict:
        """Return an expiring link for the account holder to sign in themselves."""
        return await anyio.to_thread.run_sync(connect.create, site)

    mcp_app = server.streamable_http_app(stateless_http=True, json_response=True, host="127.0.0.1")
    windows = windows_factory(connect.run, save_seconds=45)

    @contextlib.asynccontextmanager
    async def lifespan(app):
        connect.relay = Relay(
            LocalBackend(windows, novnc_dir),
            public_url.rstrip("/") + "/connect",
            text=PageText(service="Amazon", reconnect=True),
        )
        app.router.routes[:] = [*connect.relay.routes("/connect"), Mount("/", BearerTokenMiddleware(mcp_app, token))]
        app.state.connect = connect
        app.state.windows = windows
        app.state.sessions = sessions
        app.state.mcp = server
        async with mcp_app.router.lifespan_context(mcp_app), windows.lifespan(), connect.relay.lifespan():
            yield

    return Starlette(lifespan=lifespan)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--token-file", type=Path, required=True)
    parser.add_argument("--novnc-dir", type=Path, required=True)
    parser.add_argument("--public-url", default="http://127.0.0.1:8765")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--amazon", action="store_true", help="Use actual Amazon; only on an authorized deployed host")
    args = parser.parse_args()
    args.state.mkdir(parents=True, exist_ok=True)
    config = AmazonOrdersConfig(
        config_path=str(args.state / "config.yml"),
        data={"cookie_jar_path": str(args.state / "cookies.json"), "request_timeout": 10},
    )
    with contextlib.ExitStack() as stack:
        if not args.amazon:
            stack.enter_context(Provider()).configure(config)
        app = make_app(
            config,
            public_url=args.public_url,
            token=args.token_file.read_text().strip(),
            novnc_dir=args.novnc_dir,
            synthetic=not args.amazon,
        )
        uvicorn.run(app, host=args.host, port=args.port, access_log=False)


if __name__ == "__main__":
    main()
