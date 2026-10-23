"""The MCP server's client for its login service (``signin_window.service``): the service's API with its bearer,
noVNC's files, and a window's remote-desktop stream with that window's view token.

Every URL it builds is the service's base URL plus a fixed path and validated ids; it follows no redirects. This is
the default ``Backend`` of ``signin_window.relay.Relay``.
"""

from __future__ import annotations

import asyncio
import json
import re
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

WINDOW_ID = re.compile(r"[A-Za-z0-9_-]{16,40}\Z")
VIEW_TOKEN = re.compile(r"[A-Za-z0-9_-]{16,64}\Z")
# noVNC's files: up to five path segments, none starting with a dot (so never "..").
STATIC = re.compile(r"(?:[A-Za-z0-9_-][A-Za-z0-9_.-]{0,80}/){0,4}[A-Za-z0-9_-][A-Za-z0-9_.-]{0,80}\Z")
TIMEOUT = 15
MAX_BODY = 1024 * 1024
MAX_STATIC = 4 * 1024 * 1024


class LoginUnavailable(Exception):
    """The login service did not answer as expected."""


class LoginBusy(LoginUnavailable):
    """Every window slot of the login service is in use."""


class _NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


class LoginClient:
    """``token`` is the service's bearer; or ``token_file``, read on every call (so it can be rotated)."""

    def __init__(self, base_url: str, token: str | None = None, *, token_file: str | Path | None = None) -> None:
        if (token is None) == (token_file is None):
            raise ValueError("give exactly one of token and token_file")
        if not re.match(r"https?://", base_url):
            raise ValueError("base_url must be http(s)")
        self.base = base_url.rstrip("/")
        self._token, self._token_file = token, Path(token_file) if token_file is not None else None
        self._opener = urllib.request.build_opener(_NoRedirects())

    def _authorization(self) -> str:
        if self._token_file is not None:
            try:
                token = self._token_file.read_text(encoding="utf-8").strip()
            except OSError:
                raise LoginUnavailable("no token") from None
        else:
            token = self._token or ""
        if not token:
            raise LoginUnavailable("no token")
        return f"Bearer {token}"

    def _raw(self, method: str, path: str, body: dict[str, Any] | None = None, limit: int = MAX_BODY):
        request = urllib.request.Request(  # noqa: S310 (base is checked to be http(s) in __init__)
            self.base + path,
            data=json.dumps(body).encode() if body is not None else None,
            method=method,
            headers={"Authorization": self._authorization(), "Content-Type": "application/json"},
        )
        try:
            with self._opener.open(request, timeout=TIMEOUT) as response:
                return response.status, response.read(limit + 1), response.headers.get("Content-Type", "")
        except urllib.error.HTTPError as err:
            return err.code, err.read(limit + 1), err.headers.get("Content-Type", "")
        except (urllib.error.URLError, TimeoutError, OSError):
            raise LoginUnavailable("unreachable") from None

    def _call(self, method: str, path: str, body: dict[str, Any] | None = None) -> tuple[int, Any]:
        status, raw, _ = self._raw(method, path, body)
        if len(raw) > MAX_BODY:
            raise LoginUnavailable("too large")
        try:
            return status, json.loads(raw) if raw else None
        except ValueError:
            raise LoginUnavailable("not json") from None

    @staticmethod
    def _id(window_id: str) -> str:
        if not WINDOW_ID.match(window_id or ""):
            raise LoginUnavailable("bad id")
        return window_id

    def start(self, layout: str = "desktop", **params: Any) -> dict[str, Any]:
        """Open a window: {id, state, view_token, ...}. ``params`` go to the service's ``start_params``."""
        status, body = self._call("POST", "/logins", {**params, "layout": layout})
        if status == 503:
            raise LoginBusy("busy")
        if status != 201 or not isinstance(body, dict) or not body.get("id") or not body.get("view_token"):
            raise LoginUnavailable(f"start {status}")
        self._id(body["id"])
        return body

    def state(self, window_id: str) -> dict[str, Any]:
        status, body = self._call("GET", f"/logins/{self._id(window_id)}")
        if status == 404:
            return {"state": "unknown"}
        if status != 200 or not isinstance(body, dict):
            raise LoginUnavailable(f"state {status}")
        return body

    def result(self, window_id: str) -> dict[str, Any] | None:
        """The handed-over session, once; None if there is none (any more)."""
        status, body = self._call("POST", f"/logins/{self._id(window_id)}/result")
        if status in (404, 409):
            return None
        if status != 200 or not isinstance(body, dict):
            raise LoginUnavailable(f"result {status}")
        return body

    def close(self, window_id: str) -> None:
        try:
            self._call("DELETE", f"/logins/{self._id(window_id)}")
        except LoginUnavailable:
            pass

    def static(self, path: str) -> tuple[int, bytes, str]:
        """One of noVNC's files, for a person's viewer: (status, body, content type)."""
        if not STATIC.match(path):
            return 404, b"", "text/plain"
        status, raw, content_type = self._raw("GET", f"/novnc/{path}", limit=MAX_STATIC)
        if len(raw) > MAX_STATIC:
            return 502, b"", "text/plain"
        return status, raw, content_type

    async def bridge(self, window_id: str, view_token: str, ws: Any) -> None:
        """Relay a person's viewer (a Starlette WebSocket) to the window's remote-desktop stream, bytes unchanged."""
        from starlette.websockets import WebSocketDisconnect
        from websockets.asyncio.client import connect
        from websockets.exceptions import WebSocketException

        if not VIEW_TOKEN.match(view_token or ""):
            raise LoginUnavailable("bad token")
        url = "ws" + self.base[len("http") :] + f"/logins/{self._id(window_id)}/vnc?t={view_token}"
        try:
            async with connect(
                url, additional_headers={"Authorization": self._authorization()}, subprotocols=["binary"],
                max_size=None,
            ) as upstream:  # fmt: skip

                async def to_window() -> None:
                    while True:
                        message = await ws.receive()
                        if message["type"] == "websocket.disconnect":
                            return
                        await upstream.send(message.get("bytes") or (message.get("text") or "").encode())

                async def to_person() -> None:
                    async for data in upstream:
                        await ws.send_bytes(data if isinstance(data, bytes) else data.encode())

                tasks = [asyncio.create_task(to_window()), asyncio.create_task(to_person())]
                await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
                for task in tasks:
                    task.cancel()
        except (OSError, WebSocketException, WebSocketDisconnect, RuntimeError):
            pass
