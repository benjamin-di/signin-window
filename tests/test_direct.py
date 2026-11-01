"""Single-consent owner discovery and sequence-ordered revocation races."""

import asyncio
import secrets
import threading
from dataclasses import replace
from urllib.parse import parse_qs, urlsplit

import httpx2
import pytest
from authlib.integrations.httpx_client import OAuth2Client
from test_delegation import BASE, ISSUER, RESOURCE, Provider

from signin_window import delegation
from signin_window.delegation import OAuthConfig, OAuthError
from signin_window.direct import DirectOAuthManager


@pytest.fixture
def direct(tmp_path, monkeypatch):
    config = OAuthConfig(
        issuer=ISSUER,
        client_id="example-client",
        client_secret=secrets.token_urlsafe(32),
        resource=RESOURCE,
        redirect_uri=BASE + "/connections/callback",
        public_base_url=BASE,
        callback_path="/connections/callback",
        scope="availability:use",
        store_key=b"k" * 32,
    )
    provider = Provider(config)
    transport = httpx2.MockTransport(provider)

    def client(*args, **kwargs):
        return OAuth2Client(*args, **kwargs, transport=transport)

    def http(_self):
        return httpx2.Client(
            trust_env=False,
            follow_redirects=False,
            timeout=8,
            event_hooks={"response": [delegation._bounded]},
            transport=transport,
        )

    monkeypatch.setattr(delegation, "OAuth2Client", client)
    monkeypatch.setattr(DirectOAuthManager, "_http", http)
    manager = DirectOAuthManager(config, tmp_path, required_groups={"example-app"})
    return manager, provider


def begin(manager, provider, owner, browser=None):
    cookie, session = browser or manager.new_browser()
    location = manager.authorize(cookie, session["csrf"])
    query = {key: values[0] for key, values in parse_qs(urlsplit(location).query).items()}
    assert query["code_challenge_method"] == "S256"
    assert query["client_id"] == manager.config.client_id
    assert query["redirect_uri"] == BASE + "/connections/callback"
    assert query["resource"] == RESOURCE
    code = "code-" + query["state"]
    provider.codes[code] = {
        "subject": "subject-" + owner,
        "nonce": query["nonce"],
        "challenge": query["code_challenge"],
    }
    return cookie, {"state": query["state"], "code": code}


def complete(manager, provider, owner, flow):
    provider.claim_changes.update(person_id=owner, groups=["example-app"])
    return manager.finish_direct_callback(*flow)


def test_two_people_use_one_client_and_separate_grants_sessions_and_cookie_rotation(direct):
    manager, provider = direct
    first = begin(manager, provider, "user-a")
    second = begin(manager, provider, "user-b")
    cookie_a, session_a = complete(manager, provider, "user-a", first)
    cookie_b, session_b = complete(manager, provider, "user-b", second)
    assert session_a["owner"] == "user-a" and session_b["owner"] == "user-b"
    assert cookie_a != first[0] and cookie_b != second[0]
    assert manager.browser_session(cookie_a) == session_a
    assert manager.browser_session(cookie_b) == session_b
    assert manager.connected("user-a") and manager.connected("user-b")
    assert manager.revision("user-a") == manager.revision("user-b") == "1"
    with pytest.raises(OAuthError):
        manager.browser_session(first[0])
    with pytest.raises(OAuthError):
        manager.finish_direct_callback(*first)


def test_csrf_browser_mixup_and_callback_replay_are_rejected(direct):
    manager, provider = direct
    browser = manager.new_browser()
    with pytest.raises(OAuthError):
        manager.authorize(browser[0], "wrong")
    flow = begin(manager, provider, "user-a", browser)
    other = manager.new_browser()
    with pytest.raises(OAuthError):
        manager.finish_direct_callback(other[0], flow[1])
    cookie, session = complete(manager, provider, "user-a", flow)
    with pytest.raises(OAuthError):
        manager.disconnect_browser(cookie, "wrong")
    assert manager.connected(session["owner"])
    manager.disconnect_browser(cookie, session["csrf"])
    assert not manager.connected("user-a")
    with pytest.raises(OAuthError):
        manager.browser_session(cookie)


@pytest.mark.parametrize(
    "changes,proof",
    [
        ({"groups": []}, None),
        ({"client_id": "other-client"}, None),
        ({"person_id": "other-owner"}, None),
        ({}, "different-owner"),
    ],
)
def test_claims_and_gateway_proof_both_bind_owner_and_admission(direct, changes, proof):
    manager, provider = direct
    flow = begin(manager, provider, "user-a")
    provider.claim_changes.update(person_id="user-a", groups=["example-app"])
    provider.claim_changes.update(changes)
    provider.proof_owner = proof
    with pytest.raises(OAuthError):
        manager.finish_direct_callback(*flow)
    assert not manager.connected("user-a")


def test_unknown_owner_query_is_never_authority(direct):
    manager, provider = direct
    cookie, parameters = begin(manager, provider, "user-a")
    parameters["owner"] = "user-b"
    _, session = complete(manager, provider, "user-a", (cookie, parameters))
    assert session["owner"] == "user-a" and not manager.connected("user-b")


def test_old_ownerless_flow_cannot_install_after_disconnect_but_new_consent_can(direct, monkeypatch):
    manager, provider = direct
    # All operations can share a wall-clock instant: ordering is durable sequence.
    moment = delegation.time.time()
    monkeypatch.setattr(delegation.time, "time", lambda: moment)
    current = complete(manager, provider, "user-a", begin(manager, provider, "user-a"))
    stale = begin(manager, provider, "user-a")
    manager.disconnect_browser(current[0], current[1]["csrf"])
    with pytest.raises(OAuthError):
        complete(manager, provider, "user-a", stale)
    assert not manager.connected("user-a") and manager.revision("user-a") == "2"
    fresh = complete(manager, provider, "user-a", begin(manager, provider, "user-a"))
    assert fresh[1]["owner"] == "user-a" and manager.revision("user-a") == "3"


@pytest.mark.asyncio
async def test_disconnect_while_owner_is_being_resolved_prevents_late_grant_install(direct, monkeypatch):
    manager, provider = direct
    complete(manager, provider, "user-a", begin(manager, provider, "user-a"))
    stale = begin(manager, provider, "user-a")
    entered, release = threading.Event(), threading.Event()
    real = manager._identity

    def resolving(*args):
        result = real(*args)
        entered.set()
        assert release.wait(5)
        return result

    monkeypatch.setattr(manager, "_identity", resolving)
    task = asyncio.create_task(asyncio.to_thread(complete, manager, provider, "user-a", stale))
    assert await asyncio.to_thread(entered.wait, 5)
    await asyncio.to_thread(manager.disconnect, "user-a")
    release.set()
    with pytest.raises(OAuthError):
        await task
    assert not manager.connected("user-a")


def test_barrier_ciphertext_cannot_be_swapped_between_people(direct):
    manager, provider = direct
    for owner in ("user-a", "user-b"):
        complete(manager, provider, owner, begin(manager, provider, owner))
    stale = begin(manager, provider, "user-a")
    with manager._db() as db:
        other = db.execute("SELECT encrypted FROM direct_metadata WHERE key='owner:user-b'").fetchone()[0]
        db.execute("UPDATE direct_metadata SET encrypted=? WHERE key='owner:user-a'", (other,))
    with pytest.raises(OAuthError):
        complete(manager, provider, "user-a", stale)


def test_callback_path_is_explicit_safe_and_same_origin(direct):
    manager, _ = direct
    for path in ("//other.example/callback", "/../callback", "/callback?owner=example", "callback"):
        with pytest.raises(OAuthError):
            replace(manager.config, callback_path=path, redirect_uri=BASE + path)
    with pytest.raises(OAuthError):
        replace(manager.config, redirect_uri="https://other.example/connections/callback")


@pytest.mark.asyncio
async def test_management_mutation_serializes_with_disconnect_and_rejects_stale_session(direct):
    manager, provider = direct
    cookie, session = complete(manager, provider, "user-a", begin(manager, provider, "user-a"))
    guard = manager.management_session(cookie, session["csrf"])
    assert await asyncio.to_thread(guard.__enter__) == session
    started = threading.Event()

    def disconnect():
        started.set()
        manager.disconnect_browser(cookie, session["csrf"])

    task = asyncio.create_task(asyncio.to_thread(disconnect))
    assert await asyncio.to_thread(started.wait, 5)
    await asyncio.sleep(0.05)
    assert not task.done() and manager.connected("user-a")
    guard.__exit__(None, None, None)
    await task
    with pytest.raises(OAuthError), manager.management_session(cookie, session["csrf"]):
        pytest.fail("stale session entered the mutation guard")


def test_anonymous_browser_budgets_do_not_exhaust_other_browsers(direct):
    manager, provider = direct
    victim = manager.new_browser()
    for _ in range(40):
        manager.new_browser()
    flow = begin(manager, provider, "user-a", victim)
    assert complete(manager, provider, "user-a", flow)[1]["owner"] == "user-a"


def test_group_iterators_preserve_the_admission_floor_and_strings_are_rejected(direct, tmp_path):
    manager, _ = direct
    configured = DirectOAuthManager(manager.config, tmp_path / "iterator", required_groups=(g for g in ["example-app"]))
    assert configured.required_groups == frozenset({"example-app"})
    with pytest.raises(OAuthError, match="oauth_configuration_invalid"):
        DirectOAuthManager(manager.config, tmp_path / "invalid", required_groups="example-app")
