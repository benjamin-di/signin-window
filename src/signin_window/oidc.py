"""Optional OIDC browser authentication; applications retain account and permission policy.

Install ``signin-window[oidc]``. Only the configured identity provider receives
protocol requests. Provider credentials, backend accounts and connection controls
never belong in this browser session store.
"""

from __future__ import annotations

import hashlib
import math
import os
import re
import secrets
import sqlite3
import stat
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from authlib.integrations.starlette_client import OAuth
from starlette.requests import HTTPConnection, Request
from starlette.responses import RedirectResponse, Response
from starlette.routing import Route

_SID = re.compile(r"[A-Za-z0-9_-]{43}\Z")
_CLAIM = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}\Z")
_MAX_AGE = 900


@dataclass(frozen=True)
class OIDCConfig:
    issuer: str
    client_id: str
    public_url: str
    state_dir: Path
    cookie_name: str = "__Host-signin-window"
    required_group: str = ""
    claim_names: tuple[str, ...] = ("person_id",)
    client_secret: str | None = field(default=None, repr=False)
    allow_loopback_http: bool = False

    def __post_init__(self):
        for value in (self.issuer, self.public_url):
            parts = urlsplit(value)
            local = self.allow_loopback_http and parts.hostname in ("127.0.0.1", "localhost")
            if (
                (parts.scheme != "https" and not (local and parts.scheme == "http"))
                or not parts.hostname
                or parts.username
                or parts.password
                or parts.query
                or parts.fragment
                or not re.fullmatch(r"(?:/[A-Za-z0-9_.~-]+)*", parts.path)
                or any(segment in (".", "..") for segment in parts.path.split("/"))
                or any(c.isspace() for c in value)
            ):
                raise ValueError("OIDC addresses must be fixed HTTPS URLs without query or fragment")
        if not self.client_id or not re.fullmatch(r"__Host-[A-Za-z0-9_-]{1,64}", self.cookie_name):
            raise ValueError("OIDC requires a client id and a distinct __Host- cookie name")
        if len(self.claim_names) > 32 or any(not _CLAIM.fullmatch(name) for name in self.claim_names):
            raise ValueError("Select a bounded list of application identity claims")


class BrowserStore:
    """Bounded opaque browser sessions in an owned private directory, without tokens."""

    def __init__(self, folder: Path, *, clock=time.time):
        if os.name != "posix":
            raise ValueError("Hosted browser sessions require POSIX private file permissions")
        folder = Path(folder)
        folder.mkdir(parents=True, mode=0o700, exist_ok=True)
        if (
            folder.is_symlink()
            or not folder.is_dir()
            or folder.stat().st_mode & 0o077
            or folder.stat().st_uid != os.getuid()
        ):
            raise ValueError("Browser state must be an owned private directory (0700)")
        self.path, self.clock = folder / "browser.sqlite3", clock
        fd = os.open(self.path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        if (
            self.path.stat().st_mode & 0o077
            or not stat.S_ISREG(self.path.stat().st_mode)
            or self.path.stat().st_uid != os.getuid()
        ):
            raise ValueError("Browser state must be an owned private file (0600)")
        with self.db() as db:
            db.execute("CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, data TEXT, expires REAL)")

    @contextmanager
    def db(self):
        db = sqlite3.connect(self.path, timeout=5)
        try:
            with db:
                yield db
        finally:
            db.close()

    @staticmethod
    def digest(sid):
        return hashlib.sha256(sid.encode()).hexdigest()

    def load(self, sid):
        import json

        if not isinstance(sid, str) or not _SID.fullmatch(sid):
            return {}
        with self.db() as db:
            row = db.execute(
                "SELECT data FROM sessions WHERE id=? AND expires>?", (self.digest(sid), self.clock())
            ).fetchone()
        return json.loads(row[0]) if row else {}

    def save(self, sid, data):
        import json

        if not _SID.fullmatch(sid):
            raise ValueError("Invalid browser session reference")
        expires = min(self.clock() + _MAX_AGE, float(data.get("expires", self.clock() + _MAX_AGE)))
        encoded = json.dumps(data)
        if not math.isfinite(expires) or len(encoded) > 65536:
            raise ValueError("Browser session exceeds its bounds")
        with self.db() as db:
            db.execute("DELETE FROM sessions WHERE expires<=?", (self.clock(),))
            db.execute(
                "DELETE FROM sessions WHERE id IN (SELECT id FROM sessions ORDER BY expires DESC LIMIT -1 OFFSET 4095)"
            )
            db.execute("INSERT OR REPLACE INTO sessions VALUES (?,?,?)", (self.digest(sid), encoded, expires))

    def delete(self, sid):
        with self.db() as db:
            db.execute("DELETE FROM sessions WHERE id=?", (self.digest(sid),))

    def consume(self, sid):
        """Claim a pending callback once, including concurrent requests in other workers."""
        if not isinstance(sid, str) or not _SID.fullmatch(sid):
            return False
        with self.db() as db:
            row = db.execute(
                "DELETE FROM sessions WHERE id=? AND expires>? RETURNING id", (self.digest(sid), self.clock())
            ).fetchone()
        return row is not None


class BrowserAuth:
    """Code + PKCE + nonce login through Authlib, with application-owned authorization."""

    def __init__(self, config: OIDCConfig, *, clock=time.time, transport=None):
        self.config = config
        self.store = BrowserStore(config.state_dir, clock=clock)
        self.cookie = (
            config.cookie_name.removeprefix("__Host-") + "-test" if config.allow_loopback_http else config.cookie_name
        )
        self.prefix = urlsplit(config.public_url).path.rstrip("/")
        self.home = self.prefix + "/connections/"
        self.origin = "{0.scheme}://{0.netloc}".format(urlsplit(config.public_url))
        self.oauth = OAuth()
        kwargs = {
            "scope": "openid profile groups",
            "code_challenge_method": "S256",
            "token_endpoint_auth_method": "client_secret_basic" if config.client_secret else "none",
            "timeout": 10,
            "follow_redirects": False,
        }
        if transport is not None:
            kwargs["transport"] = transport
        self.client = self.oauth.register(
            "identity",
            client_id=config.client_id,
            client_secret=config.client_secret,
            server_metadata_url=config.issuer + "/.well-known/openid-configuration",
            client_kwargs=kwargs,
        )

    def identity(self, request: HTTPConnection):
        data = self.store.load(request.cookies.get(self.cookie, ""))
        if (
            data.get("issuer") != self.config.issuer
            or not isinstance(data.get("sub"), str)
            or not data["sub"]
            or not isinstance(data.get("groups"), list)
            or not all(isinstance(group, str) for group in data["groups"])
            or (self.config.required_group and self.config.required_group not in data["groups"])
            or not isinstance(data.get("claims"), dict)
            or float(data.get("expires", 0)) <= self.store.clock()
        ):
            return None
        return {
            "issuer": data["issuer"],
            "sub": data["sub"],
            "name": str(data.get("name") or "Your account")[:100],
            "groups": list(data["groups"]),
            "claims": dict(data["claims"]),
            "expires": data["expires"],
            "auth_time": data.get("auth_time"),
            "reauthenticated_at": data.get("reauthenticated_at"),
        }

    def origin_ok(self, request: HTTPConnection):
        return request.headers.getlist("origin") == [self.origin]

    def _destination(self, value):
        if value == self.home or re.fullmatch(re.escape(self.prefix + "/connect/") + r"[A-Za-z0-9_-]{32,64}", value):
            return value
        return self.home

    async def login(self, request: Request):
        destination = self._destination(request.query_params.get("next", self.home))
        request.session.clear()
        request.session["next"] = destination
        step_up = request.query_params.get("reauth") == "1"
        if step_up:
            request.session["reauth_started"] = self.store.clock()
        try:
            metadata = await self.client.load_server_metadata()
            if metadata.get("issuer") != self.config.issuer:
                raise ValueError("issuer mismatch")
            for name in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
                endpoint = urlsplit(metadata.get(name, ""))
                local = self.config.allow_loopback_http and endpoint.hostname in ("127.0.0.1", "localhost")
                if (
                    not endpoint.hostname
                    or endpoint.username
                    or endpoint.password
                    or endpoint.fragment
                    or (endpoint.scheme != "https" and not (local and endpoint.scheme == "http"))
                ):
                    raise ValueError("identity endpoint must use HTTPS")
            return await self.client.authorize_redirect(
                request,
                self.config.public_url + "/connections/callback",
                **({"prompt": "login", "max_age": 0} if step_up else {}),
            )
        except Exception:
            request.session.clear()
            return Response(
                "Identity provider could not be verified. Return to connections and try again.", status_code=503
            )

    async def callback(self, request: Request):
        destination = self._destination(request.session.get("next", self.home))
        reauth_started = request.session.get("reauth_started")
        try:
            if not self.store.consume(request.cookies.get(self.cookie, "")):
                raise ValueError("callback already consumed")
            token = await self.client.authorize_access_token(
                request, claims_options={"iss": {"essential": True, "value": self.config.issuer}}, leeway=0
            )
            info = token.get("userinfo") or {}
            sub, groups = info.get("sub"), info.get("groups", [])
            if (
                info.get("iss") != self.config.issuer
                or not isinstance(sub, str)
                or not sub
                or not isinstance(groups, list)
                or not all(isinstance(group, str) for group in groups)
                or (self.config.required_group and self.config.required_group not in groups)
            ):
                raise ValueError("identity refused")
            expires = min(float(info["exp"]), self.store.clock() + _MAX_AGE)
            if not math.isfinite(expires) or expires <= self.store.clock():
                raise ValueError("identity expired")
            authenticated = info.get("auth_time")
            if reauth_started is not None and (
                not isinstance(authenticated, int | float)
                or isinstance(authenticated, bool)
                or not math.isfinite(authenticated)
                or authenticated < reauth_started - 5
                or authenticated > self.store.clock() + 5
            ):
                raise ValueError("fresh authentication was not verified")
            request.session.clear()
            request.session.update(
                issuer=self.config.issuer,
                sub=sub,
                groups=groups,
                name=str(info.get("name") or "Your account")[:100],
                expires=expires,
                claims={name: info[name] for name in self.config.claim_names if name in info},
                auth_time=authenticated,
                reauthenticated_at=self.store.clock() if reauth_started is not None else None,
            )
            request.scope["rotate_browser_session"] = True
            return RedirectResponse(destination, status_code=303)
        except Exception:
            request.session.clear()
            return Response("Sign-in could not be verified. Return to connections and try again.", status_code=403)

    async def logout(self, request: Request):
        if not self.origin_ok(request):
            return Response("Request refused", status_code=403)
        request.session.clear()
        return RedirectResponse(self.home, status_code=303)

    def routes(self, prefix="/connections"):
        return [
            Route(prefix + "/login", self.login),
            Route(prefix + "/callback", self.callback),
            Route(prefix + "/logout", self.logout, methods=["POST"]),
        ]

    def middleware(self, app):
        auth = self

        async def wrapped(scope, receive, send):
            if scope["type"] != "http":
                return await app(scope, receive, send)
            request = HTTPConnection(scope)
            old = request.cookies.get(auth.cookie, "")
            original = auth.store.load(old)
            scope["session"] = dict(original)

            async def respond(message):
                if message["type"] == "http.response.start":
                    data = scope["session"]
                    if data != original or scope.get("rotate_browser_session"):
                        auth.store.delete(old)
                        sid = secrets.token_urlsafe(32)
                        if data:
                            auth.store.save(sid, data)
                        cookie = Response()
                        cookie.set_cookie(
                            auth.cookie,
                            sid if data else "",
                            max_age=_MAX_AGE if data else 0,
                            path="/",
                            httponly=True,
                            samesite="lax",
                            secure=not auth.config.allow_loopback_http,
                        )
                        message.setdefault("headers", []).append((b"set-cookie", cookie.headers["set-cookie"].encode()))
                    if scope.get("path", "").startswith((auth.prefix + "/connections/", "/connections/")):
                        message.setdefault("headers", []).extend(
                            [
                                (b"cache-control", b"no-store"),
                                (b"referrer-policy", b"strict-origin"),
                                (b"x-frame-options", b"DENY"),
                                (b"x-content-type-options", b"nosniff"),
                            ]
                        )
                        headers = message["headers"]
                        if not any(name.lower() == b"content-security-policy" for name, _ in headers):
                            headers.append(
                                (
                                    b"content-security-policy",
                                    b"default-src 'self'; script-src 'none'; style-src 'self' "
                                    b"'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
                                )
                            )
                await send(message)

            await app(scope, receive, respond)

        return wrapped
