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

from anyio import CancelScope

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


class LocalBackend:
    """Embed windows beside an application's login code, without an HTTP service.

    Construct on the host's running event loop. Relay calls the synchronous methods
    from worker threads; browser/profile ownership stays with the supplied runner.
    Mount both ``windows.lifespan()`` and ``relay.lifespan()`` in the host.
    """

    def __init__(self, windows: Any, novnc_dir: str | Path) -> None:
        self.windows = windows
        self.novnc_dir = Path(novnc_dir).resolve()
        self.loop = asyncio.get_running_loop()

    def _run(self, operation):
        # A synchronous call on the host loop would deadlock that same loop.
        try:
            current = asyncio.get_running_loop()
        except RuntimeError:
            current = None
        if current is self.loop:
            operation.close()
            raise RuntimeError("call LocalBackend from a worker thread")
        return asyncio.run_coroutine_threadsafe(operation, self.loop).result()

    def start(self, layout: str = "desktop", **params: Any) -> dict[str, Any]:
        from .service import Busy

        try:
            window = self._run(self.windows.start(layout, params))
        except Busy:
            raise LoginBusy("busy") from None
        except (OSError, RuntimeError, ValueError):
            raise LoginUnavailable("could not start the local window") from None
        return {**window.public(), "view_token": window.view_token}

    def state(self, window_id: str) -> dict[str, Any]:
        async def read():
            window = self.windows.get(window_id)
            return window.public() if window else {"state": "unknown"}

        return self._run(read())

    def result(self, window_id: str) -> dict[str, Any] | None:
        async def take():
            return self.windows.take(window_id)

        return self._run(take())

    def close(self, window_id: str) -> None:
        self._run(self.windows.close(window_id))

    def static(self, path: str, window_id: str | None = None) -> tuple[int, bytes, str]:
        import mimetypes

        if not STATIC.fullmatch(path):
            return 404, b"", ""
        file = (self.novnc_dir / path).resolve()
        if not file.is_relative_to(self.novnc_dir) or not file.is_file():
            return 404, b"", ""
        try:
            with file.open("rb") as stream:
                data = stream.read(MAX_STATIC + 1)
        except OSError:
            return 404, b"", ""
        if len(data) > MAX_STATIC:
            return 404, b"", ""
        return 200, data, mimetypes.guess_type(path)[0] or "application/octet-stream"

    async def bridge(self, window_id: str, view_token: str, ws: Any) -> None:
        from .service import _pipe

        window = self.windows.get(window_id)
        if window is None or not window.view_ok(view_token) or window.state != "waiting":
            await ws.close(code=4404)
            return
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", window.vnc_port)
        except OSError:
            raise LoginUnavailable("local viewer unavailable") from None
        await _pipe(ws, reader, writer, lambda: window.state == "waiting")


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

    def request(self, method: str, path: str, body: dict[str, Any] | None = None) -> tuple[int, Any]:
        """Call one of your own routes on the login service (``build_app(routes=...)``), with its bearer: (status,
        JSON body). ``path`` is a fixed path you build from validated parts."""
        if not path.startswith("/") or ".." in path or "//" in path:
            raise LoginUnavailable("bad path")
        return self._call(method, path, body)

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

    def static(self, path: str, window_id: str | None = None) -> tuple[int, bytes, str]:
        """One of noVNC's files, for a person's viewer: (status, body, content type). The service serves the same files
        for every window, so ``window_id`` (which window the viewer is for) is not needed here."""
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
                try:
                    await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
                finally:
                    for task in tasks:
                        task.cancel()
                    with CancelScope(shield=True):
                        await asyncio.gather(*tasks, return_exceptions=True)
        except (OSError, WebSocketException, WebSocketDisconnect, RuntimeError):
            pass
