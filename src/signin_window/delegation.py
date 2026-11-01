"""Optional owner-scoped delegated OAuth; synchronous operations run in worker threads.

Browser capabilities and OAuth grants are private application state. Neither a
model argument nor a callback parameter selects the owner of a stored grant.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import fcntl
import hashlib
import hmac
import html
import json
import math
import os
import re
import secrets
import sqlite3
import stat
import time
from contextlib import closing, contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import parse_qs, quote, urlsplit

import httpx2
import jwt
from authlib.integrations.httpx_client import OAuth2Client
from authlib.oauth2.rfc7523 import PrivateKeyJWT
from authlib.oidc.core import CodeIDToken
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from starlette.responses import HTMLResponse, RedirectResponse

MAX_BODY = 65536
LIFETIME = 600
LOCK_WAIT = 30
COOKIE = "__Secure-delegated-oauth"
IDENTITY_SCOPES = {"openid", "profile", "email", "offline_access"}
SAFE_HEADERS = {
    "Cache-Control": "no-store",
    # A no-referrer policy makes a browser's form POST send Origin: null.
    # Keep the real same-origin Origin for CSRF checks and omit cross-site referrers.
    "Referrer-Policy": "same-origin",
    "X-Content-Type-Options": "nosniff",
}


class OAuthError(Exception):
    """A fixed error code with no provider diagnostics or account data."""

    def __init__(self, code="oauth_reconnect_required"):
        super().__init__(
            code
            if code
            in {
                "oauth_reconnect_required",
                "oauth_connection_invalid",
                "oauth_busy",
                "oauth_configuration_invalid",
            }
            else "oauth_reconnect_required"
        )
        self.code = str(self)


def _url(value):
    if (
        not isinstance(value, str)
        or len(value) > 2048
        or any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in value)
    ):
        raise OAuthError("oauth_configuration_invalid")
    try:
        parsed = urlsplit(value)
        _ = parsed.port
    except ValueError:
        raise OAuthError("oauth_configuration_invalid") from None
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise OAuthError("oauth_configuration_invalid")
    return parsed


def _owner(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", value):
        raise OAuthError("oauth_connection_invalid")
    return value


def _hash(value):
    return hashlib.sha256(value.encode()).hexdigest()


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _bounded(response):
    body = bytearray()
    for chunk in response.iter_bytes():
        body.extend(chunk)
        if len(body) > MAX_BODY:
            response.close()
            raise OAuthError()
    response._content = bytes(body)
    if not 200 <= response.status_code < 300:
        raise OAuthError()


@dataclass(frozen=True)
class OAuthConfig:
    issuer: str
    client_id: str
    client_secret: str = field(repr=False)
    resource: str
    redirect_uri: str
    public_base_url: str
    scope: str
    store_key: str | bytes = field(repr=False)
    client_private_key: str | bytes | None = field(default=None, repr=False)
    owner_header: str = "X-Authenticated-User"
    cookie_name: str = COOKIE
    callback_path: str = "/oauth/callback"

    @property
    def auth_method(self):
        return "private_key_jwt" if self.client_private_key is not None else "client_secret_basic"

    def __post_init__(self):
        for value in (self.issuer, self.resource, self.redirect_uri, self.public_base_url):
            _url(value)
        if (
            self.issuer.endswith("/")
            or self.public_base_url.endswith("/")
            or not isinstance(self.callback_path, str)
            or not re.fullmatch(r"/(?:[A-Za-z0-9_-]+/)*[A-Za-z0-9_-]+", self.callback_path)
            or self.redirect_uri != self.public_base_url + self.callback_path
            or not isinstance(self.client_id, str)
            or not 1 <= len(self.client_id) <= 200
            or any(c.isspace() for c in self.client_id)
            or not isinstance(self.scope, str)
        ):
            raise OAuthError("oauth_configuration_invalid")
        if self.client_private_key is None:
            if (
                not isinstance(self.client_secret, str)
                or not 16 <= len(self.client_secret) <= 4096
                or any(c in self.client_secret for c in "\r\n\0")
            ):
                raise OAuthError("oauth_configuration_invalid")
        else:
            if self.client_secret:
                raise OAuthError("oauth_configuration_invalid")
            try:
                key_bytes = self.client_private_key
                if isinstance(key_bytes, str):
                    key_bytes = key_bytes.encode()
                key = serialization.load_pem_private_key(key_bytes, password=None)
                if not isinstance(key, rsa.RSAPrivateKey) or key.key_size < 2048:
                    raise ValueError
            except (TypeError, ValueError):
                raise OAuthError("oauth_configuration_invalid") from None
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9-]{0,100}", self.owner_header) or not re.fullmatch(
            r"__Secure-[A-Za-z0-9_-]{1,64}", self.cookie_name
        ):
            raise OAuthError("oauth_configuration_invalid")
        scopes = self.scope.split()
        if (
            not scopes
            or len(scopes) != len(set(scopes))
            or bool(set(scopes) & IDENTITY_SCOPES)
            or any(not re.fullmatch(r"[A-Za-z0-9:._-]{1,128}", s) for s in scopes)
        ):
            raise OAuthError("oauth_configuration_invalid")
        try:
            key = self.store_key
            if isinstance(key, str):
                if not re.fullmatch(r"[A-Za-z0-9_-]{43}=?", key):
                    raise ValueError
                key = base64.b64decode(key + "=" * (-len(key) % 4), altchars=b"-_", validate=True)
            if not isinstance(key, bytes) or len(key) != 32:
                raise ValueError
        except (ValueError, binascii.Error):
            raise OAuthError("oauth_configuration_invalid") from None


def public_client_jwk(private_key: str | bytes) -> dict:
    """Return only the RSA public key and its RFC 7638 thumbprint for enrollment."""
    try:
        encoded = private_key.encode() if isinstance(private_key, str) else private_key
        key = serialization.load_pem_private_key(encoded, password=None)
        if not isinstance(key, rsa.RSAPrivateKey) or key.key_size < 2048:
            raise ValueError
        public = jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key(), as_dict=True)
        canonical = {name: public[name] for name in ("e", "kty", "n")}
        digest = hashlib.sha256(_json(canonical)).digest()
        return {
            **canonical,
            "kid": base64.urlsafe_b64encode(digest).rstrip(b"=").decode(),
            "alg": "RS256",
            "use": "sig",
        }
    except (TypeError, ValueError):
        raise OAuthError("oauth_configuration_invalid") from None


def create_client_key(directory: Path) -> dict:
    """Provision once; return a public JWK and refuse to replace any existing key.

    This is an explicit enrollment operation, never a deployment startup hook.
    Lost/revoked keys require application-owned recovery, not automatic enrollment.
    """
    directory = Path(directory)
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    if directory.is_symlink() or directory.stat().st_uid != os.getuid() or directory.stat().st_mode & 0o077:
        raise OAuthError("oauth_configuration_invalid")
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    encoded = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    descriptor = os.open(directory / "client.pem", os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(encoded)
        stream.flush()
        os.fsync(stream.fileno())
    from .state import fsync_directory

    fsync_directory(directory)
    return public_client_jwk(encoded)


def load_client_key(directory: Path) -> bytes:
    """Read an already provisioned private key; missing keys are never recreated."""
    directory = Path(directory)
    if directory.is_symlink() or directory.stat().st_uid != os.getuid() or directory.stat().st_mode & 0o077:
        raise OAuthError("oauth_configuration_invalid")
    descriptor = os.open(directory / "client.pem", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        metadata = os.fstat(stream.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid() or metadata.st_mode & 0o077:
            raise OAuthError("oauth_configuration_invalid")
        encoded = stream.read(8193)
    if len(encoded) > 8192:
        raise OAuthError("oauth_configuration_invalid")
    public_client_jwk(encoded)
    return encoded


class OAuthManager:
    def __init__(self, config: OAuthConfig, state_dir: Path):
        self.config = config
        key = config.store_key
        if isinstance(key, str):
            key = base64.urlsafe_b64decode(key + "=" * (-len(key) % 4))
        self.cipher = AESGCM(key)
        self.directory = Path(state_dir) / "oauth"
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.directory.is_symlink() or self.directory.stat().st_uid != os.getuid():
            raise OAuthError("oauth_configuration_invalid")
        self.directory.chmod(0o700)
        self.path = self.directory / "grants.sqlite"
        descriptor = os.open(self.path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            if not stat.S_ISREG(os.fstat(descriptor).st_mode) or os.fstat(descriptor).st_uid != os.getuid():
                raise OAuthError("oauth_configuration_invalid")
            os.fchmod(descriptor, 0o600)
        finally:
            os.close(descriptor)
        with self._db() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS accounts (
                    owner TEXT PRIMARY KEY, subject TEXT NOT NULL, generation TEXT NOT NULL,
                    status TEXT NOT NULL, encrypted BLOB);
                CREATE TABLE IF NOT EXISTS capabilities (
                    digest TEXT PRIMARY KEY, kind TEXT NOT NULL, owner TEXT NOT NULL,
                    expires REAL NOT NULL, encrypted BLOB NOT NULL);
            """)

    @contextmanager
    def _db(self):
        db = sqlite3.connect(self.path, timeout=5, isolation_level=None)
        db.row_factory = sqlite3.Row
        try:
            db.execute("PRAGMA secure_delete=ON")
            db.execute("BEGIN IMMEDIATE")
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    @contextmanager
    def _lock(self, owner):
        owner = _owner(owner)
        descriptor = os.open(self.directory / (_hash(owner) + ".lock"), os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            if not stat.S_ISREG(os.fstat(descriptor).st_mode) or os.fstat(descriptor).st_uid != os.getuid():
                raise OAuthError("oauth_configuration_invalid")
            os.fchmod(descriptor, 0o600)
            deadline = time.monotonic() + LOCK_WAIT
            while True:
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise OAuthError("oauth_busy") from None
                    time.sleep(0.02)
            yield
        finally:
            os.close(descriptor)

    def _aad(self, kind, owner, binding):
        return _json([1, kind, owner, self.config.issuer, self.config.client_id, self.config.resource, binding])

    def _encrypt(self, kind, owner, binding, value):
        nonce = secrets.token_bytes(12)
        return nonce + self.cipher.encrypt(nonce, _json(value), self._aad(kind, owner, binding))

    def _decrypt(self, kind, owner, binding, value):
        try:
            return json.loads(self.cipher.decrypt(value[:12], value[12:], self._aad(kind, owner, binding)))
        except Exception:
            raise OAuthError() from None

    def _account(self, owner):
        # A single read-only SELECT is a committed snapshot. Status checks must
        # never wait on the owner lock held by refresh network operations.
        try:
            with closing(sqlite3.connect(self.path.absolute().as_uri() + "?mode=ro", uri=True, timeout=0.05)) as db:
                db.row_factory = sqlite3.Row
                row = db.execute("SELECT * FROM accounts WHERE owner=?", (owner,)).fetchone()
        except sqlite3.Error:
            raise OAuthError() from None
        if row is None:
            return {
                "owner": owner,
                "subject": "",
                "generation": "0",
                "status": "disconnected",
                "encrypted": None,
            }
        account = dict(row)
        if (
            not isinstance(account["generation"], str)
            or not re.fullmatch(r"[1-9][0-9]{0,18}", account["generation"])
            or account["status"] not in {"connected", "uncertain", "disconnected"}
            or not isinstance(account["subject"], str)
            or not isinstance(account["encrypted"], bytes)
        ):
            raise OAuthError()
        grant = self._grant(account)
        if account["status"] == "disconnected":
            if grant != {"disconnected": True}:
                raise OAuthError()
        elif not isinstance(grant, dict) or grant.get("subject") != account["subject"]:
            raise OAuthError()
        return account

    def _grant(self, account):
        return self._decrypt(
            "grant",
            account["owner"],
            [account["subject"], account["generation"], account["status"]],
            account["encrypted"],
        )

    def _save(self, account, grant=None):
        encrypted = self._encrypt(
            "grant",
            account["owner"],
            [account["subject"], account["generation"], account["status"]],
            {"disconnected": True} if grant is None else grant,
        )
        with self._db() as db:
            db.execute(
                "INSERT INTO accounts VALUES (?,?,?,?,?) ON CONFLICT(owner) DO UPDATE SET "
                "subject=excluded.subject,generation=excluded.generation,status=excluded.status,"
                "encrypted=excluded.encrypted",
                (account["owner"], account["subject"], account["generation"], account["status"], encrypted),
            )

    def _cap(self, kind, token, *, consume=False):
        if not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", token):
            raise OAuthError("oauth_connection_invalid")
        digest = _hash(kind + ":" + token)
        with self._db() as db:
            row = db.execute("SELECT * FROM capabilities WHERE digest=? AND kind=?", (digest, kind)).fetchone()
            if not row or row["expires"] <= time.time():
                raise OAuthError("oauth_connection_invalid")
            payload = self._decrypt(kind, row["owner"], [digest, row["expires"]], row["encrypted"])
            if consume:
                db.execute("DELETE FROM capabilities WHERE digest=?", (digest,))
        return row["owner"], payload

    def _new_cap(self, kind, owner, payload):
        token = secrets.token_urlsafe(32)
        self._write_cap(kind, token, owner, payload)
        return token

    def _write_cap(self, kind, token, owner, payload):
        digest = _hash(kind + ":" + token)
        expires = time.time() + LIFETIME
        with self._db() as db:
            db.execute("DELETE FROM capabilities WHERE expires<=?", (time.time(),))
            if db.execute("SELECT COUNT(*) FROM capabilities WHERE owner=?", (owner,)).fetchone()[0] >= 32:
                raise OAuthError("oauth_busy")
            db.execute(
                "INSERT OR REPLACE INTO capabilities VALUES (?,?,?,?,?)",
                (digest, kind, owner, expires, self._encrypt(kind, owner, [digest, expires], payload)),
            )

    def connected(self, owner):
        return self._account(_owner(owner))["status"] == "connected"

    def revision(self, owner):
        return self._account(_owner(owner))["generation"]

    def connection_url(self, owner):
        with self._lock(owner):
            ticket = self._new_cap("ticket", owner, {"generation": self._account(owner)["generation"]})
        return self.config.public_base_url + "/oauth/connect/" + ticket

    def _http(self):
        return httpx2.Client(trust_env=False, follow_redirects=False, timeout=8, event_hooks={"response": [_bounded]})

    def _endpoint(self, value):
        parsed, issuer = _url(value), _url(self.config.issuer)
        if (parsed.scheme, parsed.netloc) != (issuer.scheme, issuer.netloc):
            raise OAuthError("oauth_configuration_invalid")
        return value

    def _metadata(self):
        try:
            with self._http() as client:
                value = client.get(self.config.issuer + "/.well-known/openid-configuration").json()
            if (
                not isinstance(value, dict)
                or value.get("issuer") != self.config.issuer
                or "S256" not in value.get("code_challenge_methods_supported", [])
                or self.config.auth_method not in value.get("token_endpoint_auth_methods_supported", [])
            ):
                raise OAuthError()
            for field_name in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
                self._endpoint(value[field_name])
            if "revocation_endpoint" in value:
                self._endpoint(value["revocation_endpoint"])
            return value
        except Exception:
            raise OAuthError() from None

    def _client(self):
        client = OAuth2Client(
            self.config.client_id,
            self.config.client_private_key or self.config.client_secret,
            scope=self.config.scope + " openid offline_access",
            redirect_uri=self.config.redirect_uri,
            token_endpoint_auth_method=self.config.auth_method,
            code_challenge_method="S256",
            revocation_endpoint_auth_method=self.config.auth_method,
            trust_env=False,
            follow_redirects=False,
            timeout=8,
            event_hooks={"response": [_bounded]},
        )

        if self.config.client_private_key is not None:
            client.register_client_auth_method(
                PrivateKeyJWT(
                    token_endpoint=self.config.issuer,
                    alg="RS256",
                    headers={"kid": public_client_jwk(self.config.client_private_key)["kid"]},
                )
            )
        return client

    def _keys(self, metadata):
        with self._http() as client:
            value = client.get(metadata["jwks_uri"]).json()
        if not isinstance(value, dict) or not isinstance(value.get("keys"), list) or not 1 <= len(value["keys"]) <= 16:
            raise OAuthError()
        keys = {}
        key_values = value["keys"]
        for value in key_values:
            if (
                not isinstance(value, dict)
                or value.get("kty") != "RSA"
                or value.get("alg", "RS256") != "RS256"
                or value.get("use", "sig") != "sig"
                or value.get("key_ops", ["verify"]) != ["verify"]
                or any(k in value for k in ("d", "p", "q", "dp", "dq", "qi", "oth"))
                or not isinstance(value.get("kid"), str)
                or not 1 <= len(value["kid"]) <= 128
                or value["kid"] in keys
            ):
                raise OAuthError()
            key = jwt.PyJWK.from_dict(value, algorithm="RS256").key
            if key.key_size < 2048:
                raise OAuthError()
            keys[value["kid"]] = key
        return keys

    def _decode(self, value, keys, audience, *, access=False):
        if not isinstance(value, str) or len(value) > 16384:
            raise OAuthError()
        header = jwt.get_unverified_header(value)
        if (
            header.get("alg") != "RS256"
            or header.get("typ") not in ({"at+jwt"} if access else {None, "JWT"})
            or any(k in header for k in ("crit", "jku", "jwk", "x5u"))
            or header.get("kid") not in keys
        ):
            raise OAuthError()
        claims = jwt.decode(
            value,
            keys[header["kid"]],
            algorithms=["RS256"],
            issuer=self.config.issuer,
            audience=audience,
            options={"require": ["iss", "sub", "aud", "exp", "iat"]},
        )
        if (
            not isinstance(claims["sub"], str)
            or not 1 <= len(claims["sub"]) <= 255
            or any(
                type(claims[k]) not in (int, float) or not math.isfinite(claims[k])
                for k in ("iat", "exp", "nbf")
                if k in claims
            )
            or claims["iat"] >= claims["exp"]
        ):
            raise OAuthError()
        audiences = claims["aud"] if isinstance(claims["aud"], list) else [claims["aud"]]
        allowed = {audience, self.config.issuer} if access else {audience}
        if audience not in audiences or len(audiences) != len(set(audiences)) or not set(audiences) <= allowed:
            raise OAuthError()
        return claims, header

    def _validate(self, token, metadata, nonce, *, subject=None, initial=False):
        if not isinstance(token, dict) or str(token.get("token_type", "")).lower() != "bearer":
            raise OAuthError()
        keys = self._keys(metadata)
        access, _ = self._decode(token.get("access_token"), keys, self.config.resource, access=True)
        scopes = access.get("scope", "").split()
        required = set(self.config.scope.split()) - IDENTITY_SCOPES
        if (
            not required <= set(scopes)
            or not set(scopes) <= set(self.config.scope.split()) | {"openid", "offline_access"}
            or ("client_id" in access and access["client_id"] != self.config.client_id)
            or (subject is not None and access["sub"] != subject)
        ):
            raise OAuthError()
        if initial or token.get("id_token"):
            claims, header = self._decode(token.get("id_token"), keys, self.config.client_id)
            params = {"client_id": self.config.client_id, "access_token": token["access_token"]}
            if initial or "nonce" in claims:
                params["nonce"] = nonce
            CodeIDToken(claims, header, params=params).validate()
            if claims["sub"] != access["sub"]:
                raise OAuthError()
        refresh = token.get("refresh_token")
        if not isinstance(refresh, str) or not 16 <= len(refresh) <= 16384:
            raise OAuthError()
        return {"token": dict(token), "subject": access["sub"], "expires_at": access["exp"], "nonce": nonce}

    def _prove_owner(self, owner, token):
        message = {
            "jsonrpc": "2.0",
            "id": "delegated-oauth",
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": {"name": "delegated-oauth", "version": "1"},
            },
        }
        with self._http() as client:
            response = client.post(
                self.config.resource,
                json=message,
                headers={"Authorization": "Bearer " + token, "Accept": "application/json, text/event-stream"},
            )
        value = response.json()
        if (
            response.headers.get(self.config.owner_header) != owner
            or response.headers.get("Mcp-Session-Id")
            or value.get("jsonrpc") != "2.0"
            or value.get("id") != message["id"]
            or "error" in value
            or not isinstance(value.get("result"), dict)
            or value["result"].get("isError")
        ):
            raise OAuthError()

    def open_browser(self, ticket):
        owner, _ = self._cap("ticket", ticket)
        with self._lock(owner):
            _, payload = self._cap("ticket", ticket)
            account = self._account(owner)
            if payload["generation"] != account["generation"]:
                raise OAuthError("oauth_connection_invalid")
            # Preview scanners and reloads must not claim an owner's link.
            # Only a cookie-bound, CSRF-checked POST consumes the ticket.
            session = {
                "csrf": secrets.token_urlsafe(32),
                "generation": account["generation"],
                "ticket": ticket,
            }
            cookie = self._new_cap("browser", owner, session)
            return cookie, session["csrf"], account["status"] == "connected"

    def _browser(self, cookie):
        owner, session = self._cap("browser", cookie)
        if session["generation"] != self._account(owner)["generation"]:
            raise OAuthError("oauth_connection_invalid")
        return owner, session

    def browser_action(self, cookie, csrf, action):
        owner, _ = self._cap("browser", cookie)
        revoke = None
        with self._lock(owner):
            owner, session = self._browser(cookie)
            if not isinstance(csrf, str) or not hmac.compare_digest(csrf, session["csrf"]):
                raise OAuthError("oauth_connection_invalid")
            if action not in ("connect", "disconnect"):
                raise OAuthError("oauth_connection_invalid")
            account = self._account(owner)
            if ticket := session.get("ticket"):
                ticket_owner, payload = self._cap("ticket", ticket)
                if ticket_owner != owner or payload["generation"] != account["generation"]:
                    raise OAuthError("oauth_connection_invalid")
                self._cap("ticket", ticket, consume=True)
                session = {k: v for k, v in session.items() if k != "ticket"}
                self._write_cap("browser", cookie, owner, session)
            if action == "connect":
                metadata = self._metadata()
                verifier, nonce = secrets.token_urlsafe(48), secrets.token_urlsafe(32)
                state = self._new_cap(
                    "state",
                    owner,
                    {
                        "browser": _hash(cookie),
                        "verifier": verifier,
                        "nonce": nonce,
                        "generation": account["generation"],
                        "metadata": metadata,
                    },
                )
                with self._client() as client:
                    location, _ = client.create_authorization_url(
                        metadata["authorization_endpoint"],
                        state=state,
                        code_verifier=verifier,
                        nonce=nonce,
                        resource=self.config.resource,
                        prompt="consent",
                    )
                return {"redirect": location}
            if action != "disconnect":
                raise OAuthError("oauth_connection_invalid")
            revoke = self._clear(account)
            session = {"csrf": secrets.token_urlsafe(32), "generation": self._account(owner)["generation"]}
            self._write_cap("browser", cookie, owner, session)
        self._revoke(revoke)
        return {"csrf": session["csrf"], "connected": False}

    def finish_callback(self, cookie, parameters):
        # OAuth responses may include scope and provider extensions. Ignore
        # fields we do not consume; authority comes from state and signed tokens.
        if not isinstance(parameters, dict):
            raise OAuthError("oauth_connection_invalid")
        state = parameters.get("state", "")
        owner, _ = self._cap("state", state)
        with self._lock(owner):
            browser_owner, _ = self._browser(cookie)
            if browser_owner != owner:
                raise OAuthError("oauth_connection_invalid")
            _, flow = self._cap("state", state)
            if not hmac.compare_digest(flow["browser"], _hash(cookie)):
                raise OAuthError("oauth_connection_invalid")
            self._cap("state", state, consume=True)
            account = self._account(owner)
            code = parameters.get("code")
            if (
                flow["generation"] != account["generation"]
                or "error" in parameters
                or parameters.get("iss", self.config.issuer) != self.config.issuer
                or not isinstance(code, str)
                or not 1 <= len(code) <= 4096
                or any(c.isspace() for c in code)
            ):
                raise OAuthError("oauth_connection_invalid")
            try:
                with self._client() as client:
                    token = client.fetch_token(
                        flow["metadata"]["token_endpoint"],
                        grant_type="authorization_code",
                        code=code,
                        code_verifier=flow["verifier"],
                        resource=self.config.resource,
                    )
                grant = self._validate(token, flow["metadata"], flow["nonce"], initial=True)
                if account["subject"] and account["subject"] != grant["subject"]:
                    raise OAuthError()
                self._prove_owner(owner, token["access_token"])
                account.update(
                    subject=grant["subject"],
                    generation=str(int(account["generation"]) + 1),
                    status="connected",
                )
                session = {"csrf": secrets.token_urlsafe(32), "generation": account["generation"]}
                self._write_cap("browser", cookie, owner, session)
                self._save(account, grant)
                return {"csrf": session["csrf"], "connected": True}
            except Exception:
                raise OAuthError() from None

    def _clear(self, account):
        try:
            token = self._grant(account).get("token") if account["encrypted"] else None
        except OAuthError:
            token = None
        account.update(generation=str(int(account["generation"]) + 1), status="disconnected")
        self._save(account)
        with self._db() as db:
            db.execute("DELETE FROM capabilities WHERE owner=? AND kind='state'", (account["owner"],))
        return token

    def disconnect(self, owner):
        with self._lock(owner):
            token = self._clear(self._account(owner))
        self._revoke(token)

    def _revoke(self, token):
        if not token:
            return
        try:
            metadata = self._metadata()
            endpoint = metadata.get("revocation_endpoint")
            if endpoint:
                with self._client() as client:
                    client.revoke_token(
                        endpoint,
                        token=token["refresh_token"],
                        token_type_hint="refresh_token",  # noqa: S106 -- RFC 7009 hint
                    )
        except Exception:
            return  # Local disconnect has committed; never expose or log provider diagnostics.

    def access_token(self, owner, minimum_ttl=0):
        if type(minimum_ttl) not in (int, float) or not math.isfinite(minimum_ttl) or not 0 <= minimum_ttl <= 900:
            raise OAuthError()
        with self._lock(owner):
            account = self._account(owner)
            if account["status"] != "connected":
                raise OAuthError()
            grant = self._grant(account)
            try:
                metadata = self._metadata()
                if grant["expires_at"] >= time.time() + minimum_ttl:
                    self._validate(grant["token"], metadata, grant["nonce"], subject=account["subject"])
                    return grant["token"]["access_token"]
            except Exception:
                raise OAuthError() from None
            # Commit uncertainty BEFORE a one-use refresh leaves this process.
            # A crash/cancellation cannot leave an old access token usable later.
            account["status"] = "uncertain"
            self._save(account, grant)
            try:
                with self._client() as client:
                    token = client.refresh_token(
                        metadata["token_endpoint"],
                        refresh_token=grant["token"]["refresh_token"],
                        resource=self.config.resource,
                    )
                new = self._validate(token, metadata, grant["nonce"], subject=account["subject"])
                if new["expires_at"] < time.time() + minimum_ttl:
                    raise OAuthError()
                account["status"] = "connected"
                self._save(account, new)
                return new["token"]["access_token"]
            except BaseException:
                account["status"] = "uncertain"
                account["generation"] = str(int(account["generation"]) + 1)
                self._save(account, grant)
                raise OAuthError() from None


def _headers(manager):
    issuer = urlsplit(manager.config.issuer)
    # Browsers apply form-action to the authorization redirect as well as the
    # initial same-origin POST. Permit only the configured issuer's origin.
    origin = quote(f"{issuer.scheme}://{issuer.netloc}", safe=":/[]")
    return {
        **SAFE_HEADERS,
        "Content-Security-Policy": (
            f"default-src 'none'; form-action 'self' {origin}; frame-ancestors 'none'; base-uri 'none'"
        ),
    }


def _page(manager, csrf=None, connected=False, *, failed=False):
    action = manager.config.public_base_url + "/oauth/action"
    text = (
        "Connection could not be completed. Request a new connection link."
        if failed
        else (
            "The connection is active." if connected else "Connect to permit this application to act with your consent."
        )
    )
    forms = ""
    if csrf:
        for name, label in (("connect", "Connect / reconnect"), ("disconnect", "Disconnect")):
            forms += (
                f'<form method="post" action="{html.escape(action, quote=True)}">'
                f'<input type="hidden" name="csrf" value="{html.escape(csrf, quote=True)}">'
                f'<button name="action" value="{name}">{label}</button></form>'
            )
    return HTMLResponse(
        "<!doctype html><title>Application connection</title><h1>Application connection</h1>"
        + f"<p>{text}</p>"
        + forms,
        headers=_headers(manager),
        status_code=400 if failed else 200,
    )


def register_routes(mcp, manager):
    """Register the exact public browser surface; all blocking work runs off-loop."""
    cookie_path = urlsplit(manager.config.public_base_url).path + "/oauth"
    cookie_name = manager.config.cookie_name

    @mcp.custom_route("/oauth/connect/{ticket}", methods=["GET"])
    async def connect(request):
        try:
            if request.url.query:
                raise OAuthError()
            cookie, csrf, connected = await asyncio.to_thread(manager.open_browser, request.path_params["ticket"])
            response = _page(manager, csrf, connected)
            response.set_cookie(
                cookie_name, cookie, max_age=LIFETIME, path=cookie_path, secure=True, httponly=True, samesite="lax"
            )
            return response
        except Exception:
            return _page(manager, failed=True)

    @mcp.custom_route("/oauth/action", methods=["POST"])
    async def action(request):
        try:
            origin = urlsplit(manager.config.public_base_url)
            if (
                request.url.query
                or request.headers.get("origin") != f"{origin.scheme}://{origin.netloc}"
                or request.headers.get("content-type", "").split(";", 1)[0] != "application/x-www-form-urlencoded"
            ):
                raise OAuthError()
            body = bytearray()
            async for chunk in request.stream():
                body.extend(chunk)
                if len(body) > 2048:
                    raise OAuthError()
            values = parse_qs(body.decode(), strict_parsing=True)
            if set(values) != {"csrf", "action"} or any(len(v) != 1 for v in values.values()):
                raise OAuthError()
            result = await asyncio.to_thread(
                manager.browser_action, request.cookies.get(cookie_name), values["csrf"][0], values["action"][0]
            )
            if "redirect" in result:
                return RedirectResponse(result["redirect"], status_code=303, headers=_headers(manager))
            return _page(manager, result["csrf"], result["connected"])
        except Exception:
            return _page(manager, failed=True)

    @mcp.custom_route("/oauth/callback", methods=["GET"])
    async def callback(request):
        try:
            if len(request.url.query) > 8192 or any(
                len(request.query_params.getlist(k)) != 1 for k in request.query_params
            ):
                raise OAuthError()
            result = await asyncio.to_thread(
                manager.finish_callback, request.cookies.get(cookie_name), dict(request.query_params)
            )
            return _page(manager, result["csrf"], result["connected"])
        except Exception:
            return _page(manager, failed=True)
