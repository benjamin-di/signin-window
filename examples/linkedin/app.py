"""Optional login surface around upstream's own LinkedIn login child."""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import sys
from dataclasses import asdict
from pathlib import Path

from linkedin_mcp_server.config import load_config
from linkedin_mcp_server.profile_claim import ensure_profile_claim
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route

from signin_window.child import run_child
from signin_window.client import LocalBackend
from signin_window.page import PageText
from signin_window.relay import Relay
from signin_window.service import Windows
from signin_window.state import atomic_private_write

WORKER = Path(__file__).with_name("worker.py")


def make_app(
    config, *, display, public_url, token, novnc_dir, synthetic=True, fail_export=False, windows_factory=Windows
):
    if len(token) < 32:
        raise ValueError("a token of at least 32 characters is required")
    ensure_profile_claim(Path(config.browser.user_data_dir))

    async def login(window):
        private = Path(window.temp_profile("login-settings-")) / "config.json"
        atomic_private_write(private, json.dumps(asdict(config)).encode())
        argv = [sys.executable, str(WORKER), "--config", str(private)]
        if synthetic:
            argv.append("--synthetic")
        if fail_export:
            argv.append("--fail-export")
        allowed = (
            "PATH",
            "LD_LIBRARY_PATH",
            "LANG",
            "LC_ALL",
            "TZ",
            "XDG_CONFIG_DIRS",
            "XDG_DATA_DIRS",
            "PLAYWRIGHT_BROWSERS_PATH",
            "XKB_CONFIG_ROOT",
        )
        env = window.env({name: os.environ[name] for name in allowed if name in os.environ})
        # Browser support files belong to this child, never the host's settings directory.
        env["XDG_CONFIG_HOME"] = str(private.parent / "config")
        env["XDG_CACHE_HOME"] = str(private.parent / "cache")
        return await run_child(window, argv, env=env, kept=True, stop_seconds=45)

    windows = windows_factory(login, display=display, save_seconds=60)

    @contextlib.asynccontextmanager
    async def lifespan(app):
        relay = Relay(
            LocalBackend(windows, novnc_dir),
            public_url.rstrip("/") + "/connect",
            text=PageText(service="LinkedIn", reconnect=True).with_outcomes(
                failed="<h1>Sign-in could not be confirmed</h1><p>Return to the application to check its session.</p>"
            ),
        )

        async def link(request):
            import hmac

            if not hmac.compare_digest(request.headers.get("authorization", ""), "Bearer " + token):
                return JSONResponse({"error": "unauthorized"}, status_code=401)
            created = relay.create("account")
            return JSONResponse({"url": created.url, "expires_at": created.expires_at})

        app.router.routes[:] = [Route("/link", link, methods=["POST"]), *relay.routes("/connect")]
        app.state.relay, app.state.windows = relay, windows
        async with windows.lifespan(), relay.lifespan():
            yield

    return Starlette(lifespan=lifespan)


def main():
    import uvicorn

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--token-file", type=Path, required=True)
    parser.add_argument("--novnc-dir", type=Path, required=True)
    parser.add_argument("--display", required=True)
    parser.add_argument("--port", type=int, default=8766)
    parser.add_argument("--synthetic", action="store_true", required=True)
    args = parser.parse_args()
    config = load_config()
    config.browser.user_data_dir = str(args.profile)
    config.validate()
    app = make_app(
        config,
        display=args.display,
        public_url=f"http://127.0.0.1:{args.port}",
        token=args.token_file.read_text().strip(),
        novnc_dir=args.novnc_dir,
        synthetic=args.synthetic,
    )
    uvicorn.run(app, host="127.0.0.1", port=args.port, access_log=False)


if __name__ == "__main__":
    main()
