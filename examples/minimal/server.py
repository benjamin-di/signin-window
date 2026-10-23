"""The server side: a sign-in link for an account, its page and live view under /connect, and the handed-over
session stored for that account (here a file per account; use your own session store).

An MCP server exposes ``connect`` as a tool, so an assistant can give the person their link::

    @mcp.tool
    def site_connect() -> dict:
        link = relay.create(current_account())
        return {"url": link.url, "expires_at": link.expires_at}

Your reverse proxy forwards ``/connect/...`` (and its WebSocket) without your server's bearer, and sets
X-Forwarded-For.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from signin_window.client import LoginClient
from signin_window.page import PageText
from signin_window.relay import Link, LinkLimited, Relay

SESSIONS = Path(os.environ.get("SESSIONS_DIR", "sessions"))


def store(link: Link, session: dict) -> str:
    """The window handed a session over for ``link.key``: keep it (atomically, owner-only) and say how it went."""
    cookies = session.get("cookies")
    if not isinstance(cookies, list) or not cookies:
        return "failed"
    SESSIONS.mkdir(mode=0o700, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=SESSIONS)
    with os.fdopen(fd, "w") as f:
        json.dump(cookies, f)
    os.replace(tmp, SESSIONS / f"{link.key}.json")
    return "connected"


relay = Relay(
    LoginClient(os.environ.get("SIGNIN_URL", "http://login:8080"), os.environ["SIGNIN_TOKEN"]),
    os.environ.get("PUBLIC_URL", "https://mcp.example.com") + "/connect",
    text=PageText(service="Example", secure_host=r"(^|\.)example\.com$"),
    on_signed_in=store,
)


async def connect(request: Request) -> JSONResponse:
    """POST /link {"account": ...}: behind your own authentication in a real server."""
    account = str((await request.json()).get("account", ""))
    if not account.isidentifier():
        return JSONResponse({"error": "account"}, status_code=400)
    try:
        link = relay.create(account)
    except LinkLimited:
        return JSONResponse({"error": "too many links this hour"}, status_code=429)
    return JSONResponse({"url": link.url, "expires_at": link.expires_at})


app = Starlette(routes=[Route("/link", connect, methods=["POST"]), *relay.routes("/connect")])
