"""Optional web authentication with real protocol verification and durable private sessions."""

import base64
import secrets
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from urllib.parse import parse_qs, urlencode, urlsplit

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
    # The provider authenticated the person just now, so this sign-in already counts as a fresh confirmation.
    assert response.json()["reauthenticated_at"] == response.json()["auth_time"]
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
    ("claims", "expected"),
    [
        ({"display_name": "Example"}, "Example"),
        ({}, "Example One"),
        ({"display_name": ""}, "Example One"),
        ({"display_name": " \n\u202eExample\x00 "}, "Example"),
        ({"display_name": "x" * 200}, "x" * 100),
        ({"display_name": None, "name": None}, None),
        ({"name": "Your account"}, None),
        ({"display_name": ["untrusted"]}, "Example One"),
    ],
)
def test_display_label_is_optional_bounded_and_display_only(system, claims, expected):
    auth, provider, client = system
    provider.tamper.update(claims)
    assert sign_in(provider, client).status_code == 303
    identity = client.get("/connections/status").json()
    assert identity["label"] == expected
    assert identity["sub"] == "subject-one"
    assert identity["claims"] == {"person_id": "first"}
    assert auth.store.load(client.cookies[auth.cookie])["label"] == expected


def test_display_label_claim_can_be_configured(system):
    auth, provider, client = system
    auth.config = replace(auth.config, label_claim="short_name")
    provider.tamper.update(short_name="Short", display_name="Other")
    assert sign_in(provider, client).status_code == 303
    assert client.get("/connections/status").json()["label"] == "Short"
    with pytest.raises(ValueError, match="display label claim"):
        replace(auth.config, label_claim="bad claim")


def test_verified_missing_group_notifies_host_without_authorizing(system):
    auth, provider, client = system
    observed = []
    auth.on_group_refused = observed.append
    provider.tamper.update(groups=[])
    assert sign_in(provider, client).status_code == 403
    assert client.get("/connections/status").status_code == 401
    assert observed == [
        {
            "issuer": provider.issuer,
            "sub": "subject-one",
            "groups": [],
            "claims": {"person_id": "first"},
        }
    ]
    assert "synthetic-access-token" not in str(observed)


@pytest.mark.parametrize("tamper", [{"iss": "https://other.example.com"}, {"exp": 1}, {"sub": ""}, {"groups": "bad"}])
def test_invalid_identity_never_notifies_group_removal(system, tamper):
    auth, provider, client = system
    observed = []
    auth.on_group_refused = observed.append
    provider.tamper.update({"groups": [], **tamper})
    assert sign_in(provider, client).status_code == 403
    assert observed == []


def test_group_refusal_callback_failure_stays_closed(system):
    auth, provider, client = system

    def fail(identity):
        raise ValueError("synthetic host refusal")

    auth.on_group_refused = fail
    provider.tamper.update(groups=[])
    assert sign_in(provider, client).status_code == 403
    assert client.get("/connections/status").status_code == 401


def test_new_sign_in_notifies_host_once_with_verified_identity(system):
    auth, provider, client = system
    observed = []
    auth.on_sign_in = observed.append
    provider.tamper.update(display_name="Example")
    assert sign_in(provider, client).status_code == 303
    assert len(observed) == 1
    assert observed[0]["sub"] == "subject-one"
    assert observed[0]["label"] == "Example"
    assert observed[0]["claims"] == {"person_id": "first"}
    assert "synthetic-access-token" not in str(observed)
    assert client.get("/connections/status").status_code == 200
    assert len(observed) == 1
    provider.tamper.update(groups=[])
    assert sign_in(provider, client).status_code == 403
    assert len(observed) == 1


def test_host_sign_in_refusal_never_saves_the_new_identity(system):
    auth, provider, client = system
    assert sign_in(provider, client).status_code == 303

    def fail(identity):
        raise ValueError("synthetic host refusal")

    auth.on_sign_in = fail
    assert sign_in(provider, client).status_code == 403
    assert client.get("/connections/status").status_code == 401


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
    signed_out = client.post("/connections/logout", headers={"origin": auth.origin})
    assert signed_out.status_code == 200 and 'href="/connections/login"' in signed_out.text
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
    (tmp_path / "wide").chmod(0o755)  # Exercise an unsafe directory even under a private export umask.
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
    assert "Back to Connections" in response.text


def test_connection_pages_allow_only_the_reviewed_enhancement_script(system):
    from signin_window.connections import SCRIPT_SOURCE

    _, _, client = system
    response = client.get("/connections/status")
    policy = response.headers["content-security-policy"]
    assert f"script-src {SCRIPT_SOURCE};" in policy
    assert "script-src 'self'" not in policy and "script-src 'unsafe-inline'" not in policy
    assert "frame-ancestors 'none'" in policy and "form-action 'self'" in policy


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


@pytest.mark.parametrize("age", [301, 3600])
def test_an_older_provider_session_signs_in_but_is_not_a_fresh_confirmation(system, age):
    _, provider, client = system
    provider.tamper = {"auth_time": int(time.time()) - age}
    assert sign_in(provider, client).status_code == 303
    identity = client.get("/connections/status").json()
    assert identity["auth_time"] == provider.tamper["auth_time"] and identity["reauthenticated_at"] is None


@pytest.mark.parametrize("authenticated", [None, True, int(time.time()) + 3600])
def test_an_unverifiable_auth_time_is_never_a_fresh_confirmation(system, authenticated):
    _, provider, client = system
    provider.tamper = {"auth_time": authenticated}
    assert sign_in(provider, client).status_code == 303
    assert client.get("/connections/status").json()["reauthenticated_at"] is None


def test_a_recent_confirmation_counts_from_the_providers_authentication_time(system):
    _, provider, client = system
    provider.tamper = {"auth_time": int(time.time()) - 200}
    assert sign_in(provider, client).status_code == 303
    assert client.get("/connections/status").json()["reauthenticated_at"] == provider.tamper["auth_time"]


def stepping_app(auth):
    async def act(request):
        if auth.identity(request) is None or not auth.origin_ok(request):
            return auth.refused(request)
        return auth.require_fresh(request, action="connect an account") or JSONResponse({"done": True})

    async def status(request):
        who = auth.identity(request)
        return JSONResponse({**(who or {}), "fresh": auth.fresh(request)}, status_code=200 if who else 401)

    return auth.middleware(
        Starlette(
            routes=[
                *auth.routes(),
                Route("/connections/status", status),
                Route("/connections/act", act, methods=["POST"]),
            ]
        )
    )


@pytest.fixture
def stepping(system):
    auth, provider, _ = system
    with TestClient(stepping_app(auth), base_url=auth.config.public_url, follow_redirects=False) as client:
        yield auth, provider, client


def test_an_abandoned_or_cross_site_sign_in_start_keeps_the_verified_session(stepping):
    _, provider, client = stepping
    provider.tamper = {"auth_time": int(time.time()) - 3600}
    assert sign_in(provider, client).status_code == 303
    for start in ("/connections/login?reauth=1", "/connections/login"):
        assert client.get(start).status_code == 302
        identity = client.get("/connections/status")
        assert identity.status_code == 200 and identity.json()["sub"] == "subject-one"


def test_a_cancelled_step_up_keeps_the_session_without_freshness(stepping):
    _, provider, client = stepping
    provider.tamper = {"auth_time": int(time.time()) - 3600}
    assert sign_in(provider, client).status_code == 303
    started = client.get("/connections/login?reauth=1").headers["location"]
    state = parse_qs(urlsplit(started).query)["state"][0]
    cancelled = client.get("/connections/callback?" + urlencode({"error": "access_denied", "state": state}))
    assert cancelled.status_code == 403 and "Back to Connections" in cancelled.text
    identity = client.get("/connections/status").json()
    assert identity["sub"] == "subject-one" and identity["fresh"] is False


def test_an_unverified_step_up_keeps_the_earlier_session_without_freshness(stepping):
    _, provider, client = stepping
    provider.tamper = {"auth_time": int(time.time()) - 3600}
    assert sign_in(provider, client).status_code == 303
    assert sign_in(provider, client, "?reauth=1").status_code == 403
    identity = client.get("/connections/status").json()
    assert identity["sub"] == "subject-one" and identity["fresh"] is False


def test_a_refused_provider_identity_ends_the_earlier_session(stepping):
    _, provider, client = stepping
    assert sign_in(provider, client).status_code == 303
    provider.tamper = {"groups": []}
    assert sign_in(provider, client, "?reauth=1").status_code == 403
    assert client.get("/connections/status").status_code == 401


def test_a_forged_callback_navigation_does_not_sign_the_person_out(stepping):
    _, provider, client = stepping
    assert sign_in(provider, client).status_code == 303
    assert client.get("/connections/callback?code=forged&state=forged").status_code == 403
    assert client.get("/connections/status").json()["sub"] == "subject-one"


def test_a_step_up_started_near_session_expiry_can_still_complete(stepping):
    auth, provider, client = stepping
    provider.tamper = {"auth_time": int(time.time()) - 3600, "exp": int(time.time()) + 7200}
    assert sign_in(provider, client).status_code == 303
    start = time.time()
    auth.store.clock = lambda: start + 850
    location = client.get("/connections/login?reauth=1").headers["location"]
    auth.store.clock = lambda: start + 950  # The earlier identity has expired; the attempt has not.
    assert client.get("/connections/status").status_code == 401
    provider.tamper = {"auth_time": int(start + 940), "exp": int(time.time()) + 7200}
    assert client.get(path(provider.authorize(location))).status_code == 303
    assert client.get("/connections/status").json()["fresh"] is True


def test_require_fresh_answers_with_a_step_up_link_never_a_redirect(stepping):
    auth, provider, client = stepping
    provider.tamper = {"auth_time": int(time.time()) - 3600}
    assert sign_in(provider, client).status_code == 303
    page = client.post("/connections/act", headers={"origin": auth.origin})
    assert page.status_code == 403 and "location" not in page.headers
    assert "Confirm it&#x27;s you" in page.text and "connect an account" in page.text
    assert 'href="/connections/login?reauth=1"' in page.text
    location = client.get("/connections/login?reauth=1").headers["location"]
    provider.tamper = {}
    assert client.get(path(provider.authorize(location))).headers["location"] == "/connections/"
    assert client.post("/connections/act", headers={"origin": auth.origin}).json() == {"done": True}


def test_step_up_links_return_only_to_safe_local_pages(system):
    auth, _, _ = system
    attempt = "/connect/" + "a" * 32
    assert auth.step_up_url() == "/connections/login?reauth=1"
    assert auth.step_up_url(attempt) == "/connections/login?reauth=1&next=" + attempt
    for unsafe in ("https://other.example.com", "//other.example.com", "/connections/logout"):
        assert auth.step_up_url(unsafe) == "/connections/login?reauth=1"


def test_refusals_explain_themselves_instead_of_redirecting(stepping):
    auth, provider, client = stepping
    signed_out = client.post("/connections/act", headers={"origin": auth.origin})
    assert signed_out.status_code == 401 and "location" not in signed_out.headers
    assert "Your sign-in has ended" in signed_out.text and 'href="/connections/login"' in signed_out.text
    assert sign_in(provider, client).status_code == 303
    foreign = client.post("/connections/act", headers={"origin": "https://other.example.com"})
    assert foreign.status_code == 403 and "Request refused" in foreign.text


def test_a_callback_that_loses_the_claim_never_restores_an_ended_session(stepping):
    auth, provider, client = stepping
    assert sign_in(provider, client).status_code == 303
    location = client.get("/connections/login?reauth=1").headers["location"]
    pending = client.cookies[auth.cookie]
    callback = path(provider.authorize(location))
    provider.tamper = {"groups": []}
    assert client.get(callback).status_code == 403  # The refused identity ends the session.
    client.cookies.set(auth.cookie, pending, domain="app.example.com", path="/")
    duplicate = client.get(callback)  # The same callback again, as a retried or concurrent request.
    assert duplicate.status_code == 403 and "set-cookie" not in duplicate.headers
    assert client.get("/connections/status").status_code == 401


def test_a_callback_that_loses_a_concurrent_claim_writes_nothing(stepping, monkeypatch):
    auth, provider, client = stepping
    assert sign_in(provider, client).status_code == 303
    location = client.get("/connections/login?reauth=1").headers["location"]
    # Another request claimed this row after this one read it (a retried or concurrent callback).
    monkeypatch.setattr(auth.store, "consume", lambda sid: False)
    lost = client.get(path(provider.authorize(location)))
    assert lost.status_code == 403 and "set-cookie" not in lost.headers


def test_a_sign_in_attempt_expires_after_its_own_window(stepping):
    auth, provider, client = stepping
    provider.tamper = {"auth_time": int(time.time()) - 3600}
    assert sign_in(provider, client).status_code == 303
    start = time.time()
    location = client.get("/connections/login?reauth=1").headers["location"]
    auth.store.clock = lambda: start + 601
    provider.tamper = {"exp": int(start) + 7200}
    assert client.get(path(provider.authorize(location))).status_code == 403
    identity = client.get("/connections/status").json()
    assert identity["sub"] == "subject-one" and identity["fresh"] is False


def test_confirmation_and_refusal_pages_carry_their_own_safety_headers(stepping):
    from starlette.requests import Request

    from signin_window.oidc import PAGE_HEADERS

    auth, _, client = stepping
    bare = Request({"type": "http", "method": "GET", "path": "/connect/x", "headers": [], "query_string": b""})
    for response in (auth.require_fresh(bare), auth.refused(bare)):
        assert {name: response.headers.get(name) for name in PAGE_HEADERS} == PAGE_HEADERS
    served = client.post("/connections/act", headers={"origin": auth.origin})
    for name in PAGE_HEADERS:
        assert len(served.headers.get_list(name)) == 1
