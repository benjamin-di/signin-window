"""Synthetic hosted OAuth with real signatures, encryption and process locks."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import multiprocessing
import os
import re
import secrets
import time
from dataclasses import replace
from urllib.parse import parse_qs, urlsplit

import httpx2
import jwt
import pytest
from authlib.integrations.httpx_client import OAuth2Client
from authlib.oauth2.rfc7636 import create_s256_code_challenge
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from starlette.applications import Starlette
from starlette.routing import Route
from starlette.testclient import TestClient

from signin_window import delegation as oauth
from signin_window.delegation import OAuthConfig, OAuthError, OAuthManager, register_routes

ISSUER = "https://identity.example.com"
RESOURCE = "https://tools.example.com/availability/mcp"
BASE = "https://application.example.com"


@pytest.fixture
def config():
    return OAuthConfig(
        issuer=ISSUER,
        client_id="example-client",
        client_secret=secrets.token_urlsafe(32),
        resource=RESOURCE,
        redirect_uri=BASE + "/oauth/callback",
        public_base_url=BASE,
        scope="availability:use",
        store_key=base64.urlsafe_b64encode(b"k" * 32).decode(),
    )


class FastMCP:
    """Exercise the framework-neutral custom_route registration on Starlette."""

    def __init__(self, _name):
        self.routes = []

    def custom_route(self, path, methods):
        def register(endpoint):
            self.routes.append(Route(path, endpoint, methods=methods))
            return endpoint

        return register

    def http_app(self):
        return Starlette(routes=self.routes)


class Provider:
    def __init__(self, config):
        self.config = config
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.jwk = {
            **jwt.algorithms.RSAAlgorithm.to_jwk(self.key.public_key(), as_dict=True),
            "kid": "synthetic-key",
            "alg": "RS256",
            "use": "sig",
        }
        self.codes = {}
        self.refreshes = multiprocessing.get_context("fork").Value("i", 0)
        self.reads = []
        self.revoked = []
        self.expires = 900
        self.claim_changes = {}
        self.id_changes = {}
        self.header_changes = {}
        self.proof_owner = None
        self.fail_refresh = False
        self.crash_refresh = False
        self.revoke_failure = False
        self.refresh_entered = None
        self.refresh_release = None
        self.metadata_changes = {}
        self.http_options = []
        self.client_assertions = []

    def signed(self, subject, *, nonce=None, access=True):
        now = int(time.time())
        value = {
            "iss": ISSUER,
            "sub": subject,
            "iat": now - 1,
            "exp": now + self.expires,
            "aud": [RESOURCE, ISSUER] if access else self.config.client_id,
        }
        if access:
            value.update(scope="availability:use openid offline_access", client_id=self.config.client_id)
            value.update(self.claim_changes)
        else:
            value["nonce"] = nonce
            value.update(self.id_changes)
        headers = {"kid": "synthetic-key", "typ": "at+jwt" if access else "JWT", **self.header_changes}
        return jwt.encode(value, self.key, algorithm="RS256", headers=headers)

    def tokens(self, subject, nonce, *, initial=True):
        result = {
            "token_type": "Bearer",
            "access_token": self.signed(subject),
            "refresh_token": "synthetic-refresh-" + subject,
            "expires_in": self.expires,
        }
        if initial:
            result["id_token"] = self.signed(subject, nonce=nonce, access=False)
        return result

    def __call__(self, request):
        self.reads.append((request.method, str(request.url).split("?", 1)[0]))
        if str(request.url) == ISSUER + "/.well-known/openid-configuration":
            return httpx2.Response(
                200,
                json={
                    "issuer": ISSUER,
                    "authorization_endpoint": ISSUER + "/authorize",
                    "token_endpoint": ISSUER + "/token",
                    "jwks_uri": ISSUER + "/jwks",
                    "revocation_endpoint": ISSUER + "/revoke",
                    "code_challenge_methods_supported": ["S256"],
                    "token_endpoint_auth_methods_supported": ["client_secret_basic"],
                    **self.metadata_changes,
                },
            )
        if str(request.url) == ISSUER + "/jwks":
            return httpx2.Response(200, json={"keys": [self.jwk]})
        if str(request.url) == RESOURCE:
            token = request.headers["authorization"].removeprefix("Bearer ")
            subject = jwt.decode(token, self.key.public_key(), algorithms=["RS256"], audience=RESOURCE)["sub"]
            owner = self.proof_owner or subject.removeprefix("subject-")
            body = json.loads(request.content)
            assert body["method"] == "initialize" and "tools/call" not in request.content.decode()
            return httpx2.Response(
                200,
                headers={"X-Authenticated-User": owner},
                json={"jsonrpc": "2.0", "id": body["id"], "result": {"capabilities": {}}},
            )
        assert request.method == "POST"
        values = {k: v[0] for k, v in parse_qs(request.content.decode()).items()}
        if self.config.auth_method == "client_secret_basic":
            expected = base64.b64encode((self.config.client_id + ":" + self.config.client_secret).encode()).decode()
            assert request.headers["authorization"] == "Basic " + expected
        else:
            assert "authorization" not in request.headers
            assert values["client_assertion_type"] == "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
            public = oauth.public_client_jwk(self.config.client_private_key)
            assertion = jwt.decode(
                values["client_assertion"],
                jwt.PyJWK.from_dict(public).key,
                algorithms=["RS256"],
                audience=self.config.issuer,
                issuer=self.config.client_id,
                options={"require": ["iss", "sub", "aud", "exp", "iat", "jti"]},
            )
            assert assertion["sub"] == self.config.client_id
            assert jwt.get_unverified_header(values["client_assertion"])["kid"] == public["kid"]
            self.client_assertions.append((str(request.url), values["client_assertion"], assertion))
        if str(request.url) == ISSUER + "/revoke":
            self.revoked.append(values["token"])
            if self.revoke_failure:
                return httpx2.Response(503, text="private upstream diagnostics")
            return httpx2.Response(200, json={})
        assert str(request.url) == ISSUER + "/token"
        assert values["resource"] == RESOURCE
        if values["grant_type"] == "authorization_code":
            flow = self.codes.pop(values["code"])
            assert values["redirect_uri"] == self.config.redirect_uri
            assert create_s256_code_challenge(values["code_verifier"]) == flow["challenge"]
            return httpx2.Response(200, json=self.tokens(flow["subject"], flow["nonce"]))
        assert values["grant_type"] == "refresh_token"
        with self.refreshes.get_lock():
            self.refreshes.value += 1
            count = self.refreshes.value
        if self.refresh_entered:
            self.refresh_entered.set()
            assert self.refresh_release.wait(5)
        if self.crash_refresh:
            os._exit(7)
        if self.fail_refresh:
            raise httpx2.ReadTimeout("private rotated refresh outcome")
        if count > 1:
            return httpx2.Response(400, json={"error": "invalid_grant"})
        subject = values["refresh_token"].removeprefix("synthetic-refresh-")
        result = self.tokens(subject, None, initial=False)
        result["refresh_token"] = "rotated-synthetic-refresh-" + subject
        return httpx2.Response(200, json=result)


@pytest.fixture
def provider(config, monkeypatch):
    provider = Provider(config)
    transport = httpx2.MockTransport(provider)
    real_oauth = OAuth2Client

    def client(*args, **kwargs):
        provider.http_options.append(kwargs)
        return real_oauth(*args, **kwargs, transport=transport)

    def http(_self):
        return httpx2.Client(
            trust_env=False,
            follow_redirects=False,
            timeout=8,
            event_hooks={"response": [oauth._bounded]},
            transport=transport,
        )

    monkeypatch.setattr(oauth, "OAuth2Client", client)
    monkeypatch.setattr(OAuthManager, "_http", http)
    return provider


@pytest.fixture
def manager(config, tmp_path, provider):
    return OAuthManager(config, tmp_path)


def begin(manager, provider, owner):
    ticket = manager.connection_url(owner).rsplit("/", 1)[-1]
    cookie, csrf, _ = manager.open_browser(ticket)
    url = manager.browser_action(cookie, csrf, "connect")["redirect"]
    query = {k: v[0] for k, v in parse_qs(urlsplit(url).query).items()}
    assert query["code_challenge_method"] == "S256"
    assert set(query["scope"].split()) == {"openid", "offline_access", "availability:use"}
    assert query["resource"] == RESOURCE
    code = "code-" + query["state"]
    provider.codes[code] = {
        "subject": "subject-" + owner,
        "nonce": query["nonce"],
        "challenge": query["code_challenge"],
    }
    return cookie, {"state": query["state"], "code": code, "scope": query["scope"]}, query


def connected(manager, provider, owner):
    cookie, params, _ = begin(manager, provider, owner)
    manager.finish_callback(cookie, params)
    return cookie


def test_three_people_share_application_config_with_separate_encrypted_records(manager, provider):
    for owner in ("user-a", "user-b", "user-c"):
        assert not manager.connected(owner) and manager.revision(owner) == "0"
        connected(manager, provider, owner)
        assert manager.connected(owner) and manager.revision(owner) == "1"
        token = manager.access_token(owner, 400)
        claims = jwt.decode(token, provider.key.public_key(), algorithms=["RS256"], audience=RESOURCE)
        assert claims["sub"] == "subject-" + owner
        raw = manager.path.read_bytes()
        assert token.encode() not in raw and ("synthetic-refresh-subject-" + owner).encode() not in raw
    assert manager.directory.stat().st_mode & 0o777 == 0o700
    assert manager.path.stat().st_mode & 0o777 == 0o600
    assert all(v["trust_env"] is False and v["follow_redirects"] is False for v in provider.http_options)
    assert all(v["token_endpoint_auth_method"] == "client_secret_basic" for v in provider.http_options)
    assert not provider.refreshes.value


@pytest.mark.parametrize(
    "change",
    [
        {"iss": "https://other.example.com"},
        {"sub": "other-subject"},
        {"aud": [RESOURCE, "other-api"]},
        {"scope": "openid"},
        {"scope": "availability:use other:use"},
        {"client_id": "another-client"},
        {"exp": 1},
        {"iat": True},
    ],
)
def test_wrong_access_identity_audience_scope_or_dates_preserves_old_grant(manager, provider, change):
    connected(manager, provider, "user-a")
    before = manager._account("user-a")
    cookie, params, _ = begin(manager, provider, "user-a")
    provider.claim_changes = change
    with pytest.raises(OAuthError):
        manager.finish_callback(cookie, params)
    assert manager._account("user-a") == before


@pytest.mark.parametrize(
    "change",
    [
        {"nonce": "wrong"},
        {"aud": "other-client"},
        {"iss": "https://other.example.com"},
        {"sub": "other-subject"},
    ],
)
def test_wrong_id_token_never_connects(manager, provider, change):
    cookie, params, _ = begin(manager, provider, "user-a")
    provider.id_changes = change
    with pytest.raises(OAuthError):
        manager.finish_callback(cookie, params)
    assert not manager.connected("user-a") and manager.revision("user-a") == "0"


def test_owner_proof_is_required_and_existing_subject_binding_cannot_change(manager, provider):
    cookie, params, _ = begin(manager, provider, "user-a")
    provider.proof_owner = "user-b"
    with pytest.raises(OAuthError):
        manager.finish_callback(cookie, params)
    assert not manager.connected("user-a")
    provider.proof_owner = None
    connected(manager, provider, "user-a")
    manager.disconnect("user-a")
    cookie, params, _ = begin(manager, provider, "user-a")
    provider.codes[params["code"]]["subject"] = "different-subject"
    provider.proof_owner = "user-a"
    with pytest.raises(OAuthError):
        manager.finish_callback(cookie, params)
    assert not manager.connected("user-a") and manager.revision("user-a") == "2"


def test_browser_capability_state_and_csrf_cannot_select_another_owner(manager, provider):
    url = manager.connection_url("user-a")
    ticket = url.rsplit("/", 1)[-1]
    _, csrf, _ = manager.open_browser(ticket)
    manager.open_browser(ticket)
    cookie, params, _ = begin(manager, provider, "user-a")
    other, _, _ = begin(manager, provider, "user-b")
    with pytest.raises(OAuthError):
        manager.finish_callback(other, params)
    with pytest.raises(OAuthError):
        manager.browser_action(cookie, csrf, "disconnect")
    assert manager.revision("user-a") == "0"
    manager.finish_callback(cookie, params)
    with pytest.raises(OAuthError):
        manager.finish_callback(cookie, params)
    assert manager.revision("user-a") == "1"


def test_callback_extensions_cannot_select_owner_resource_or_granted_permissions(manager, provider):
    cookie, parameters, _ = begin(manager, provider, "user-a")
    parameters.update(
        scope="untrusted:admin",
        owner="user-b",
        client_id="another-client",
        resource="https://tools.example.com/other/mcp",
        provider_extension="ignored",
    )
    manager.finish_callback(cookie, parameters)
    assert manager.connected("user-a") and not manager.connected("user-b")
    claims = jwt.decode(
        manager.access_token("user-a"), provider.key.public_key(), algorithms=["RS256"], audience=RESOURCE
    )
    assert claims["sub"] == "subject-user-a"
    assert claims["client_id"] == "example-client"
    assert set(claims["scope"].split()) == {"availability:use", "openid", "offline_access"}


def test_link_previews_and_reloads_do_not_claim_the_humans_connection(manager, provider):
    server = FastMCP("synthetic-oauth")
    register_routes(server, manager)
    app = server.http_app()
    path = urlsplit(manager.connection_url("user-a")).path
    with (
        TestClient(app, base_url=BASE, follow_redirects=False) as preview,
        TestClient(app, base_url=BASE, follow_redirects=False) as browser,
    ):
        assert preview.get(path).status_code == 200
        response = preview.get(path)
        assert response.status_code == 200
        preview_csrf = re.search(r'name="csrf" value="([^"]+)"', response.text)[1]
        response = browser.get(path)
        assert response.status_code == 200
        csrf = re.search(r'name="csrf" value="([^"]+)"', response.text)[1]
        response = browser.post("/oauth/action", data={"csrf": csrf, "action": "connect"}, headers={"Origin": BASE})
        assert response.status_code == 303
        assert preview.get(path).status_code == 400
        assert (
            preview.post(
                "/oauth/action",
                data={"csrf": preview_csrf, "action": "disconnect"},
                headers={"Origin": BASE},
            ).status_code
            == 400
        )
        assert manager.revision("user-a") == "0"
        # The browser that claimed the link retains its management session.
        assert (
            browser.post(
                "/oauth/action", data={"csrf": csrf, "action": "disconnect"}, headers={"Origin": BASE}
            ).status_code
            == 200
        )
        assert manager.revision("user-a") == "1"


def test_opening_the_page_does_not_extend_the_tickets_claim_deadline(manager, monkeypatch):
    now = time.time()
    monkeypatch.setattr(oauth.time, "time", lambda: now)
    ticket = manager.connection_url("user-a").rsplit("/", 1)[-1]
    monkeypatch.setattr(oauth.time, "time", lambda: now + oauth.LIFETIME - 1)
    cookie, csrf, _ = manager.open_browser(ticket)
    monkeypatch.setattr(oauth.time, "time", lambda: now + oauth.LIFETIME + 1)
    with pytest.raises(OAuthError):
        manager.browser_action(cookie, csrf, "connect")
    assert manager.revision("user-a") == "0"


def test_disconnect_invalidates_pending_callbacks_and_revokes_but_never_revives(manager, provider):
    connected(manager, provider, "user-a")
    cookie, params, _ = begin(manager, provider, "user-a")
    provider.revoke_failure = True
    manager.disconnect("user-a")
    assert not manager.connected("user-a") and manager.revision("user-a") == "2"
    assert provider.revoked
    with pytest.raises(OAuthError):
        manager.finish_callback(cookie, params)
    with pytest.raises(OAuthError):
        manager.access_token("user-a", 0)
    assert manager.revision("user-a") == "2"


@pytest.mark.parametrize("part", ["owner", "subject", "generation", "resource", "client_id", "issuer"])
def test_aead_rejects_record_or_configuration_swapping(manager, provider, config, tmp_path, part):
    connected(manager, provider, "user-a")
    connected(manager, provider, "user-b")
    if part in {"owner", "subject", "generation"}:
        with manager._db() as db:
            if part == "owner":
                other = db.execute("SELECT encrypted FROM accounts WHERE owner='user-b'").fetchone()[0]
                db.execute("UPDATE accounts SET encrypted=? WHERE owner='user-a'", (other,))
            else:
                db.execute(
                    "UPDATE accounts SET " + part + "=? WHERE owner='user-a'",
                    ("9" if part == "generation" else "other-subject",),
                )
    else:
        value = {
            "resource": "https://tools.example.com/other/mcp",
            "issuer": "https://other.example.com",
            "client_id": "different-client",
        }[part]
        manager = OAuthManager(replace(config, **{part: value}), tmp_path)
    with pytest.raises(OAuthError):
        manager.access_token("user-a", 0)


def _parallel_read(config, directory, barrier, queue):
    try:
        barrier.wait(5)
        manager = OAuthManager(config, directory)
        token = manager.access_token("user-a", 400)
        queue.put(("ok", hashlib.sha256(token.encode()).hexdigest(), manager.revision("user-a")))
    except BaseException as error:
        queue.put(("error", type(error).__name__, str(error)))


def test_real_processes_refresh_once_and_all_reuse_atomic_rotation(manager, provider, config, tmp_path):
    provider.expires = 60
    connected(manager, provider, "user-a")
    provider.expires = 900
    ctx = multiprocessing.get_context("fork")
    barrier, queue = ctx.Barrier(4), ctx.Queue()
    workers = [ctx.Process(target=_parallel_read, args=(config, tmp_path, barrier, queue)) for _ in range(4)]
    for process in workers:
        process.start()
    results = [queue.get(timeout=15) for _ in workers]
    for process in workers:
        process.join(5)
        assert process.exitcode == 0
    assert all(v[0] == "ok" and v[2] == "1" for v in results)
    assert len({v[1] for v in results}) == 1 and provider.refreshes.value == 1
    assert manager._grant(manager._account("user-a"))["token"]["refresh_token"].startswith("rotated-")


def test_refresh_uncertainty_blocks_old_token_and_releases_lock(manager, provider):
    provider.expires = 60
    connected(manager, provider, "user-a")
    provider.fail_refresh = True
    with pytest.raises(OAuthError, match=r"^oauth_reconnect_required$"):
        manager.access_token("user-a", 400)
    assert not manager.connected("user-a") and manager.revision("user-a") == "2"
    with pytest.raises(OAuthError):
        manager.access_token("user-a", 0)
    assert provider.refreshes.value == 1


def test_process_death_after_refresh_dispatch_keeps_uncertainty_durable(manager, provider, config, tmp_path):
    provider.expires = 60
    connected(manager, provider, "user-a")
    provider.crash_refresh = True
    ctx = multiprocessing.get_context("fork")
    worker = ctx.Process(target=_parallel_read, args=(config, tmp_path, ctx.Barrier(1), ctx.Queue()))
    worker.start()
    worker.join(10)
    assert worker.exitcode == 7
    assert not manager.connected("user-a") and manager.revision("user-a") == "1"
    with pytest.raises(OAuthError):
        manager.access_token("user-a", 0)
    assert provider.refreshes.value == 1


@pytest.mark.asyncio
async def test_cancelled_awaiter_does_not_discard_a_rotated_refresh(manager, provider):
    import threading

    provider.expires = 60
    connected(manager, provider, "user-a")
    provider.expires = 900
    provider.refresh_entered, provider.refresh_release = threading.Event(), threading.Event()
    task = asyncio.create_task(asyncio.to_thread(manager.access_token, "user-a", 400))
    assert await asyncio.to_thread(provider.refresh_entered.wait, 5)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    provider.refresh_release.set()
    token = await asyncio.to_thread(manager.access_token, "user-a", 400)
    assert token and provider.refreshes.value == 1 and manager.revision("user-a") == "1"


def _hold_lock(config, directory, entered, release):
    with OAuthManager(config, directory)._lock("user-a"):
        entered.set()
        release.wait(5)


def test_cross_process_lock_timeout_is_bounded_and_releases(manager, config, tmp_path, monkeypatch):
    ctx = multiprocessing.get_context("fork")
    entered, release = ctx.Event(), ctx.Event()
    worker = ctx.Process(target=_hold_lock, args=(config, tmp_path, entered, release))
    worker.start()
    assert entered.wait(5)
    monkeypatch.setattr(oauth, "LOCK_WAIT", 0.1)
    started = time.monotonic()
    with pytest.raises(OAuthError, match="oauth_busy"):
        manager.connection_url("user-a")
    assert time.monotonic() - started < 1
    release.set()
    worker.join(5)
    assert worker.exitcode == 0 and manager.revision("user-a") == "0"


@pytest.mark.parametrize(
    "issuer,source",
    [
        ("https://identity.example.com:8443/tenant", "https://identity.example.com:8443"),
        (ISSUER + ";script-src", ISSUER + "%3Bscript-src"),
    ],
)
def test_form_policy_uses_only_issuer_origin_and_cannot_inject_directives(config, tmp_path, issuer, source):
    manager = OAuthManager(replace(config, issuer=issuer), tmp_path)
    policy = oauth._headers(manager)["Content-Security-Policy"]
    assert policy.split(";") == [
        "default-src 'none'",
        " form-action 'self' " + source,
        " frame-ancestors 'none'",
        " base-uri 'none'",
    ]


def test_browser_routes_need_capability_cookie_csrf_origin_and_never_echo_secrets(manager, provider):
    server = FastMCP("synthetic-oauth")
    register_routes(server, manager)
    with TestClient(server.http_app(), base_url=BASE, follow_redirects=False) as client:
        url = manager.connection_url("user-a")
        response = client.get(urlsplit(url).path)
        assert response.status_code == 200
        assert all(s in response.headers["set-cookie"] for s in ("Secure", "HttpOnly", "SameSite=lax", "Path=/oauth"))
        assert response.headers["cache-control"] == "no-store"
        assert response.headers["referrer-policy"] == "same-origin"
        policy = dict(
            directive.strip().split(" ", 1) for directive in response.headers["content-security-policy"].split(";")
        )
        assert policy == {
            "default-src": "'none'",
            "form-action": "'self' " + ISSUER,
            "frame-ancestors": "'none'",
            "base-uri": "'none'",
        }
        csrf = re.search(r'name="csrf" value="([^"]+)"', response.text)[1]
        action = "/oauth/action"
        assert client.post(action, data={"csrf": csrf, "action": "connect"}).status_code == 400
        for origin in ("null", "https://other.example.com"):
            assert (
                client.post(action, data={"csrf": csrf, "action": "connect"}, headers={"Origin": origin}).status_code
                == 400
            )
        assert (
            client.post(action, data={"csrf": "wrong", "action": "connect"}, headers={"Origin": BASE}).status_code
            == 400
        )
        response = client.post(action, data={"csrf": csrf, "action": "connect"}, headers={"Origin": BASE})
        assert response.status_code == 303
        assert "form-action 'self' " + ISSUER in response.headers["content-security-policy"]
        query = {k: v[0] for k, v in parse_qs(urlsplit(response.headers["location"]).query).items()}
        code = "private-callback-code"
        provider.codes[code] = {
            "subject": "subject-user-a",
            "nonce": query["nonce"],
            "challenge": query["code_challenge"],
        }
        response = client.get(
            "/oauth/callback", params={"code": code, "state": query["state"], "scope": query["scope"]}
        )
        assert response.status_code == 200 and manager.connected("user-a")
        assert code not in response.text and "subject-user-a" not in response.text
        assert client.get("/oauth/callback?code=private&state=bad&state=duplicate").status_code == 400
        assert client.get(urlsplit(url).path).status_code == 400


@pytest.mark.parametrize(
    "field,value",
    [
        ("issuer", "http://identity.example.com"),
        ("resource", "https://attacker@tools.example.com/mcp"),
        ("public_base_url", BASE + "/"),
        ("redirect_uri", "https://other.example.com/oauth/callback"),
        ("store_key", "weak-password"),
        ("store_key", b"short"),
        ("scope", "openid offline_access"),
    ],
)
def test_invalid_configuration_fails_without_network(config, field, value):
    with pytest.raises(OAuthError):
        replace(config, **{field: value})


def test_secrets_are_not_in_repr_and_wrong_metadata_cannot_redirect_credentials(manager, provider, config):
    assert config.client_secret not in repr(config) and config.store_key not in repr(config)
    provider.metadata_changes = {"token_endpoint": "https://other.example.com/token"}
    cookie, csrf, _ = manager.open_browser(manager.connection_url("user-a").rsplit("/", 1)[-1])
    with pytest.raises(OAuthError):
        manager.browser_action(cookie, csrf, "connect")
    assert not any(method == "POST" for method, _ in provider.reads)


def test_failed_atomic_rotation_save_never_reenables_the_previous_token(manager, provider, monkeypatch):
    provider.expires = 60
    connected(manager, provider, "user-a")
    provider.expires = 900
    original = manager._save

    def fail_connected_save(account, grant=None):
        if account["status"] == "connected":
            raise OSError("private save diagnostics")
        return original(account, grant)

    monkeypatch.setattr(manager, "_save", fail_connected_save)
    with pytest.raises(OAuthError):
        manager.access_token("user-a", 400)
    assert not manager.connected("user-a") and manager.revision("user-a") == "2"
    with pytest.raises(OAuthError):
        manager.access_token("user-a", 0)
    assert provider.refreshes.value == 1


def test_management_failure_before_grant_commit_preserves_previous_grant(manager, provider, monkeypatch):
    connected(manager, provider, "user-a")
    previous = manager._account("user-a")
    cookie, parameters, _ = begin(manager, provider, "user-a")
    original = manager._write_cap

    def fail_browser_write(kind, *args):
        if kind == "browser":
            raise OSError("private database diagnostics")
        return original(kind, *args)

    monkeypatch.setattr(manager, "_write_cap", fail_browser_write)
    with pytest.raises(OAuthError):
        manager.finish_callback(cookie, parameters)
    assert manager._account("user-a") == previous


def test_encrypted_pending_state_and_browser_capabilities_expire_without_identity_leaks(manager, provider):
    cookie, parameters, query = begin(manager, provider, "user-a")
    raw = manager.path.read_bytes()
    for secret in (cookie, parameters["state"], query["nonce"], query["code_challenge"]):
        assert secret.encode() not in raw
    with manager._db() as db:
        db.execute("UPDATE capabilities SET expires=0")
    with pytest.raises(OAuthError):
        manager.finish_callback(cookie, parameters)
    assert not manager.connected("user-a") and manager.revision("user-a") == "0"


@pytest.mark.parametrize(
    "metadata",
    [
        {"issuer": "https://wrong.example.com"},
        {"token_endpoint": "http://identity.example.com/token"},
        {"code_challenge_methods_supported": ["plain"]},
    ],
)
def test_untrusted_discovery_never_sends_a_credential(manager, provider, metadata):
    provider.metadata_changes = metadata
    cookie, csrf, _ = manager.open_browser(manager.connection_url("user-a").rsplit("/", 1)[-1])
    with pytest.raises(OAuthError):
        manager.browser_action(cookie, csrf, "connect")
    assert all(method == "GET" for method, _ in provider.reads)


@pytest.mark.parametrize("headers", [{"typ": "JWT"}, {"jku": "https://untrusted.example.com/keys"}])
def test_token_profile_cannot_choose_a_key_or_accept_an_id_token_as_access(manager, provider, headers):
    cookie, parameters, _ = begin(manager, provider, "user-a")
    provider.header_changes = headers
    with pytest.raises(OAuthError):
        manager.finish_callback(cookie, parameters)
    assert not manager.connected("user-a")


def test_http_response_bounds_and_redirects_fail_closed():
    request = httpx2.Request("GET", ISSUER)
    response = httpx2.Response(302, request=request, headers={"Location": "https://other.example.com"})
    with pytest.raises(OAuthError):
        oauth._bounded(response)
    response = httpx2.Response(200, request=request, content=b"x" * (oauth.MAX_BODY + 1))
    with pytest.raises(OAuthError):
        oauth._bounded(response)


def test_explicit_disconnect_before_first_connection_prevents_legacy_fallback(manager):
    manager.disconnect("new-user")
    assert not manager.connected("new-user") and manager.revision("new-user") == "1"


def test_reconnection_changes_revision_while_good_refresh_does_not(manager, provider):
    connected(manager, provider, "user-a")
    connected(manager, provider, "user-a")
    assert manager.revision("user-a") == "2"


def test_callback_failure_is_sanitized_and_does_not_log_provider_payload(manager, provider, caplog):
    cookie, params, _ = begin(manager, provider, "user-a")
    provider.id_changes = {"nonce": "private-synthetic-nonce"}
    with pytest.raises(OAuthError, match=r"^oauth_reconnect_required$"):
        manager.finish_callback(cookie, params)
    assert "private-synthetic-nonce" not in caplog.text
    assert params["code"] not in caplog.text
    assert manager.config.client_secret not in caplog.text


@pytest.mark.asyncio
async def test_disconnect_serializes_after_refresh_and_cannot_be_undone(manager, provider):
    import threading

    provider.expires = 60
    connected(manager, provider, "user-a")
    provider.expires = 900
    provider.refresh_entered, provider.refresh_release = threading.Event(), threading.Event()
    reading = asyncio.create_task(asyncio.to_thread(manager.access_token, "user-a", 400))
    assert await asyncio.to_thread(provider.refresh_entered.wait, 5)
    removing = asyncio.create_task(asyncio.to_thread(manager.disconnect, "user-a"))
    await asyncio.sleep(0.05)
    assert not removing.done()
    provider.refresh_release.set()
    await reading
    await removing
    assert not manager.connected("user-a") and manager.revision("user-a") == "2"
    assert provider.revoked == ["rotated-synthetic-refresh-subject-user-a"]


def test_aead_authenticates_uncertain_status_and_capability_expiration(manager, provider):
    provider.expires = 60
    connected(manager, provider, "user-a")
    provider.fail_refresh = True
    with pytest.raises(OAuthError):
        manager.access_token("user-a", 400)
    with manager._db() as db:
        db.execute("UPDATE accounts SET status='connected' WHERE owner='user-a'")
    with pytest.raises(OAuthError):
        manager.access_token("user-a", 0)
    ticket = manager.connection_url("user-b").rsplit("/", 1)[-1]
    with manager._db() as db:
        db.execute("UPDATE capabilities SET expires=expires+900")
    with pytest.raises(OAuthError):
        manager.open_browser(ticket)


def test_prefixed_public_base_scopes_cookie_and_callback_without_an_owner_parameter(config, tmp_path):
    config = replace(config, public_base_url=BASE + "/application", redirect_uri=BASE + "/application/oauth/callback")
    manager = OAuthManager(config, tmp_path)
    server = FastMCP("prefixed-oauth")
    register_routes(server, manager)
    path = urlsplit(manager.connection_url("opaque:owner-id")).path.removeprefix("/application")
    with TestClient(server.http_app(), base_url=BASE) as client:
        response = client.get(path)
    assert response.status_code == 200 and "Path=/application/oauth" in response.headers["set-cookie"]
    assert 'action="https://application.example.com/application/oauth/action"' in response.text
    assert "opaque:owner-id" not in response.text


def test_callback_errors_consume_state_preserve_grant_and_never_use_userinfo(manager, provider):
    connected(manager, provider, "user-a")
    before = manager._account("user-a")
    cookie, params, _ = begin(manager, provider, "user-a")
    with pytest.raises(OAuthError):
        manager.finish_callback(
            cookie,
            {
                "state": params["state"],
                "error": "access_denied",
                "error_description": "private synthetic description",
            },
        )
    with pytest.raises(OAuthError):
        manager.finish_callback(cookie, params)
    assert manager._account("user-a") == before
    assert all("userinfo" not in url for _, url in provider.reads)


@pytest.mark.asyncio
async def test_status_reads_never_wait_for_a_live_refresh_or_block_the_event_loop(manager, provider):
    import threading

    provider.expires = 60
    connected(manager, provider, "user-a")
    provider.expires = 900
    provider.refresh_entered, provider.refresh_release = threading.Event(), threading.Event()
    reading = asyncio.create_task(asyncio.to_thread(manager.access_token, "user-a", 400))
    assert await asyncio.to_thread(provider.refresh_entered.wait, 5)
    started = time.monotonic()
    try:
        # The refresh has committed uncertainty but is still waiting on I/O
        # while holding the owner flock. These calls deliberately run on-loop.
        assert manager.connected("user-a") is False
        assert manager.revision("user-a") == "1"
        assert time.monotonic() - started < 0.1
        progressed = asyncio.Event()
        asyncio.get_running_loop().call_soon(progressed.set)
        await asyncio.wait_for(progressed.wait(), 0.1)
    finally:
        provider.refresh_release.set()
        await reading
    assert manager.connected("user-a") and manager.revision("user-a") == "1"


def test_status_snapshot_reads_ignore_another_process_owner_lock(manager, config, tmp_path):
    ctx = multiprocessing.get_context("fork")
    entered, release = ctx.Event(), ctx.Event()
    worker = ctx.Process(target=_hold_lock, args=(config, tmp_path, entered, release))
    worker.start()
    assert entered.wait(5)
    started = time.monotonic()
    try:
        assert not manager.connected("user-a")
        assert manager.revision("user-a") == "0"
        assert time.monotonic() - started < 0.1
    finally:
        release.set()
        worker.join(5)
    assert worker.exitcode == 0


@pytest.mark.parametrize(
    "field,value",
    [
        ("generation", "0"),
        ("generation", "7"),
        ("status", "connected"),
        ("subject", "substituted-subject"),
        ("encrypted", None),
    ],
)
def test_disconnected_metadata_is_authenticated_and_cannot_restore_legacy_fallback(manager, provider, field, value):
    connected(manager, provider, "user-a")
    manager.disconnect("user-a")
    assert not manager.connected("user-a") and manager.revision("user-a") == "2"
    with manager._db() as db:
        db.execute("UPDATE accounts SET " + field + "=? WHERE owner='user-a'", (value,))
    with pytest.raises(OAuthError):
        manager.connected("user-a")
    with pytest.raises(OAuthError):
        manager.revision("user-a")


def test_disconnected_sentinel_survives_repeated_disconnect_and_owner_swap_is_rejected(manager):
    manager.disconnect("user-a")
    manager.disconnect("user-a")
    manager.disconnect("user-b")
    assert not manager.connected("user-a") and manager.revision("user-a") == "2"
    with manager._db() as db:
        envelope = db.execute("SELECT encrypted FROM accounts WHERE owner='user-b'").fetchone()[0]
        db.execute("UPDATE accounts SET encrypted=? WHERE owner='user-a'", (envelope,))
    with pytest.raises(OAuthError):
        manager.revision("user-a")


def test_status_reads_require_no_network_or_write_transaction(manager, provider, monkeypatch):
    connected(manager, provider, "user-a")

    def forbidden(*_args, **_kwargs):
        raise AssertionError("status must read only committed local state")

    monkeypatch.setattr(manager, "_lock", forbidden)
    monkeypatch.setattr(manager, "_db", forbidden)
    monkeypatch.setattr(manager, "_http", forbidden)
    assert manager.connected("user-a") and manager.revision("user-a") == "1"
    assert not manager.connected("unknown-user") and manager.revision("unknown-user") == "0"


def test_status_reads_see_only_a_committed_account_snapshot(manager, provider):
    connected(manager, provider, "user-a")
    with pytest.raises(RuntimeError, match="synthetic rollback"):
        with manager._db() as db:
            db.execute("UPDATE accounts SET status='uncertain',generation='8' WHERE owner='user-a'")
            started = time.monotonic()
            assert manager.connected("user-a") and manager.revision("user-a") == "1"
            assert time.monotonic() - started < 0.1
            raise RuntimeError("synthetic rollback")
    assert manager.connected("user-a") and manager.revision("user-a") == "1"


def test_private_key_jwt_uses_signed_assertions_for_exchange_refresh_and_revocation(config, tmp_path, monkeypatch):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    encoded = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    config = replace(config, client_secret="", client_private_key=encoded)
    provider = Provider(config)
    provider.metadata_changes["token_endpoint_auth_methods_supported"] = ["private_key_jwt"]
    transport = httpx2.MockTransport(provider)
    real_oauth = OAuth2Client
    monkeypatch.setattr(oauth, "OAuth2Client", lambda *args, **kwargs: real_oauth(*args, **kwargs, transport=transport))
    monkeypatch.setattr(OAuthManager, "_http", lambda _: httpx2.Client(transport=transport))
    manager = OAuthManager(config, tmp_path)
    connected(manager, provider, "user-a")
    provider.expires = 100
    # A new connection with a short-lived token forces rotation on access.
    connected(manager, provider, "user-a")
    provider.expires = 900
    manager.access_token("user-a", 400)
    assert provider.refreshes.value == 1
    manager.disconnect("user-a")
    assert provider.revoked == ["rotated-synthetic-refresh-subject-user-a"]
    assert [endpoint for endpoint, _, _ in provider.client_assertions] == [
        ISSUER + "/token",
        ISSUER + "/token",
        ISSUER + "/token",
        ISSUER + "/revoke",
    ]
    assert len({claims["jti"] for _, _, claims in provider.client_assertions}) == 4
    public_key = jwt.PyJWK.from_dict(oauth.public_client_jwk(encoded)).key
    for endpoint, signed, claims in provider.client_assertions:
        assert claims["aud"] == config.issuer
        # A provider configured for the issuer rejects endpoint-specific audiences.
        endpoint_claims = {**claims, "aud": endpoint}
        endpoint_assertion = jwt.encode(endpoint_claims, key, algorithm="RS256")
        with pytest.raises(jwt.InvalidAudienceError):
            jwt.decode(endpoint_assertion, public_key, algorithms=["RS256"], audience=config.issuer)
        with pytest.raises(jwt.InvalidAudienceError):
            jwt.decode(signed, public_key, algorithms=["RS256"], audience=endpoint)
    assert "PRIVATE KEY" not in repr(config)


def test_explicit_key_provisioning_is_private_and_never_recreates_missing_or_existing_state(tmp_path):
    directory = tmp_path / "credentials"
    public = oauth.create_client_key(directory)
    encoded = oauth.load_client_key(directory)
    assert public == oauth.public_client_jwk(encoded)
    assert set(public) == {"kty", "n", "e", "kid", "alg", "use"}
    assert directory.stat().st_mode & 0o777 == 0o700
    assert (directory / "client.pem").stat().st_mode & 0o777 == 0o600
    with pytest.raises(FileExistsError):
        oauth.create_client_key(directory)
    assert oauth.load_client_key(directory) == encoded
    (directory / "client.pem").unlink()
    with pytest.raises(FileNotFoundError):
        oauth.load_client_key(directory)
    assert not (directory / "client.pem").exists()


@pytest.mark.parametrize(
    "field,value",
    [
        ("client_private_key", "invalid"),
        ("owner_header", "Bad\r\nHeader"),
        ("cookie_name", "unsecured"),
        ("client_private_key", b""),
    ],
)
def test_private_authentication_configuration_is_bounded(config, field, value):
    with pytest.raises(OAuthError):
        replace(config, **{field: value})


def test_private_key_loading_rejects_symlinks_or_public_permissions(tmp_path):
    directory = tmp_path / "credentials"
    oauth.create_client_key(directory)
    path = directory / "client.pem"
    path.chmod(0o644)
    with pytest.raises(OAuthError):
        oauth.load_client_key(directory)
    path.chmod(0o600)
    alias = tmp_path / "alias"
    alias.symlink_to(directory, target_is_directory=True)
    with pytest.raises(OAuthError):
        oauth.load_client_key(alias)


def test_owner_proof_uses_only_the_configured_resource_response_header(config, tmp_path, monkeypatch):
    config = replace(config, owner_header="X-Example-Person")
    manager = OAuthManager(config, tmp_path)

    class Client:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def post(self, _resource, *, json, headers):
            assert "Bearer " in headers["Authorization"]
            return httpx2.Response(
                200, headers={"X-Example-Person": "user-a"}, json={"jsonrpc": "2.0", "id": json["id"], "result": {}}
            )

    monkeypatch.setattr(manager, "_http", Client)
    manager._prove_owner("user-a", "synthetic-token")
    with pytest.raises(OAuthError):
        manager._prove_owner("user-b", "synthetic-token")
