"""Optional web authentication with real protocol verification and durable private sessions."""

import base64
import secrets
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from urllib.parse import urlsplit

import pytest
from oidc_provider import Provider
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from signin_window.oidc import BrowserAuth, BrowserStore, OIDCConfig


def path(url):
    p = urlsplit(url)
    return p.path + ("?" + p.query if p.query else "")


@pytest.fixture
def system(tmp_path):
    provider = Provider()
    config = OIDCConfig(
        provider.issuer, "example-app", "https://app.example.com", tmp_path / "browser", required_group="example-users"
    )
    auth = BrowserAuth(config, transport=provider.transport())

    async def status(request):
        who = auth.identity(request)
        return JSONResponse(who or {}, status_code=200 if who else 401)

    app = auth.middleware(Starlette(routes=[*auth.routes(), Route("/connections/status", status)]))
    with TestClient(app, base_url=config.public_url, follow_redirects=False) as client:
        yield auth, provider, client


def sign_in(provider, client, suffix=""):
    response = client.get("/connections/login" + suffix)
    assert response.status_code == 302, response.text
    return client.get(path(provider.authorize(response.headers["location"])))


def test_real_pkce_claims_and_opaque_cookie_without_provider_tokens(system):
    auth, provider, client = system
    assert sign_in(provider, client).status_code == 303
    response = client.get("/connections/status")
    assert response.json()["claims"] == {"person_id": "first"}
    assert response.json()["issuer"] == provider.issuer and response.json()["sub"] == "subject-one"
    assert response.json()["reauthenticated_at"] is None
    assert response.headers["cache-control"] == "no-store"
    cookie = client.cookies[auth.cookie]
    assert len(cookie) == 43 and "subject-one" not in cookie
    data = auth.store.load(cookie)
    assert all(
        secret not in str(data)
        for secret in (
            "synthetic-access-token",
            "synthetic-refresh-token",
            "private-provider-value",
            "code_verifier",
            "nonce",
        )
    )
    assert auth.store.path.stat().st_mode & 0o077 == 0


@pytest.mark.parametrize(
    "tamper",
    [
        {"nonce": "wrong"},
        {"aud": "wrong"},
        {"iss": "https://other.example.com"},
        {"exp": 1},
        {"groups": []},
        {"groups": "example-users"},
    ],
)
def test_invalid_signed_claims_never_authorize(system, tamper):
    _, provider, client = system
    provider.tamper = tamper
    assert sign_in(provider, client).status_code == 403
    assert client.get("/connections/status").status_code == 401


def test_callback_requires_the_same_browser_and_can_only_be_used_once(system):
    auth, provider, client = system
    response = client.get("/connections/login")
    callback = path(provider.authorize(response.headers["location"]))
    before = dict(client.cookies)
    client.cookies.clear()
    assert client.get(callback).status_code == 403
    client.cookies.set(auth.cookie, before[auth.cookie], domain="app.example.com", path="/")
    assert client.get(callback).status_code == 303
    assert client.cookies[auth.cookie] != before[auth.cookie]
    assert client.get(callback).status_code == 403


def test_callback_consumption_is_atomic_across_workers(tmp_path):
    first, second = BrowserStore(tmp_path / "browser"), BrowserStore(tmp_path / "browser")
    sid = secrets.token_urlsafe(32)
    first.save(sid, {"pending": True})
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda store: store.consume(sid), [first, second]))
    assert sorted(results) == [False, True]


def test_logout_and_expiry_remove_cookie_authority(system):
    auth, provider, client = system
    assert sign_in(provider, client).status_code == 303
    assert client.post("/connections/logout", headers={"origin": "https://other.example.com"}).status_code == 403
    assert (
        client.post("/connections/logout", headers=[("origin", auth.origin), ("origin", auth.origin)]).status_code
        == 403
    )
    assert client.post("/connections/logout", headers={"origin": auth.origin}).status_code == 303
    assert client.get("/connections/status").status_code == 401
    assert sign_in(provider, client).status_code == 303
    auth.store.clock = lambda: time.time() + 901
    assert client.get("/connections/status").status_code == 401


def test_forged_headers_never_establish_identity(system):
    _, _, client = system
    assert (
        client.get(
            "/connections/status", headers={"X-Authenticated-User": "first", "Authorization": "Bearer fake"}
        ).status_code
        == 401
    )


@pytest.mark.parametrize(
    "destination", ["https://other.example.com", "//other.example.com", "/connections/logout", "/connect/short"]
)
def test_open_redirects_are_refused(system, destination):
    _, provider, client = system
    assert sign_in(provider, client, "?next=" + destination).headers["location"] == "/connections/"


def test_allowed_attempt_destination_and_fresh_owner_confirmation(system):
    _, provider, client = system
    destination = "/connect/" + "a" * 32
    response = client.get("/connections/login?reauth=1&next=" + destination)
    assert "prompt=login" in response.headers["location"] and "max_age=0" in response.headers["location"]
    assert client.get(path(provider.authorize(response.headers["location"]))).headers["location"] == destination
    identity = client.get("/connections/status").json()
    assert identity["reauthenticated_at"] >= time.time() - 10
    assert identity["auth_time"] >= time.time() - 10


@pytest.mark.parametrize("authenticated", [None, 1, True, "now"])
def test_step_up_requires_fresh_verified_auth_time(system, authenticated):
    _, provider, client = system
    provider.tamper = {"auth_time": authenticated}
    assert sign_in(provider, client, "?reauth=1").status_code == 403


def test_configuration_refuses_unsafe_origins_and_state_storage(tmp_path):
    config = OIDCConfig("https://identity.example.com", "example", "https://app.example.com", tmp_path / "state")
    for url in [
        "http://app.example.com",
        "https://user:pw@example.com/",
        "https://app.example.com/?next=x",
        "https://app.example.com/../other",
        "https://app.example.com/#fragment",
    ]:
        with pytest.raises(ValueError):
            replace(config, public_url=url)
    with pytest.raises(ValueError):
        replace(config, cookie_name="shared-cookie")
    (tmp_path / "wide").mkdir(mode=0o755)
    with pytest.raises(ValueError):
        BrowserStore(tmp_path / "wide")
    (tmp_path / "link").symlink_to(tmp_path / "wide", target_is_directory=True)
    with pytest.raises(ValueError):
        BrowserStore(tmp_path / "link")


def test_identity_failure_does_not_leak_protocol_values(system, caplog):
    _, provider, client = system
    provider.tamper = {"aud": "wrong-client"}
    response = sign_in(provider, client)
    assert response.status_code == 403
    assert "synthetic-access-token" not in response.text + caplog.text


def test_confidential_client_authentication_still_uses_pkce_and_private_tokens(tmp_path):
    provider = Provider()
    credential = secrets.token_urlsafe(32)
    config = OIDCConfig(
        provider.issuer,
        "example-app",
        "https://app.example.com",
        tmp_path / "browser",
        client_secret=credential,
        required_group="example-users",
    )
    provider.required_authorization = (
        "Basic " + base64.b64encode((config.client_id + ":" + credential).encode()).decode()
    )
    auth = BrowserAuth(config, transport=provider.transport())
    app = auth.middleware(Starlette(routes=auth.routes()))
    with TestClient(app, base_url=config.public_url, follow_redirects=False) as client:
        assert sign_in(provider, client).status_code == 303
        data = auth.store.load(client.cookies[auth.cookie])
        assert data["sub"] == "subject-one"
        assert credential not in repr(config) + str(data)


def test_application_can_supply_one_fixed_provider_form_policy_without_duplicate_csp(system):
    auth, _, _ = system
    policy = "default-src 'self'; form-action 'self' https://provider.example.com; frame-ancestors 'none'"

    async def start(_request):
        return JSONResponse({}, headers={"Content-Security-Policy": policy})

    app = auth.middleware(Starlette(routes=[Route("/connections/start", start, methods=["POST"])]))
    with TestClient(app, base_url=auth.config.public_url) as client:
        response = client.post("/connections/start")
        assert response.headers.get_list("content-security-policy") == [policy]
        assert response.headers["cache-control"] == "no-store"
