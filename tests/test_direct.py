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


def test_browser_session_lifetime_config_bounds(direct):
    manager, _ = direct
    assert manager.config.browser_idle_lifetime == 7 * 24 * 60 * 60
    assert manager.config.browser_absolute_lifetime == 30 * 24 * 60 * 60
    for kwargs in (
        {"browser_idle_lifetime": 599},
        {"browser_idle_lifetime": True},
        {"browser_absolute_lifetime": True},
        {"browser_idle_lifetime": 7200, "browser_absolute_lifetime": 3600},
        {"browser_absolute_lifetime": 91 * 24 * 60 * 60},
    ):
        with pytest.raises(OAuthError, match="oauth_configuration_invalid"):
            replace(manager.config, **kwargs)


def test_browser_session_slides_within_idle_window_and_enforces_absolute_cap(direct, tmp_path, monkeypatch):
    import time as real_time

    manager, provider = direct
    now = [real_time.time()]
    monkeypatch.setattr("signin_window.delegation.time.time", lambda: now[0])
    monkeypatch.setattr("signin_window.direct.time.time", lambda: now[0])
    cfg = replace(manager.config, browser_idle_lifetime=3600, browser_absolute_lifetime=10000)
    short = DirectOAuthManager(cfg, tmp_path / "sliding", required_groups={"example-app"})

    # Create both an anonymous direct-entry cookie and an authenticated direct-browser session at t=0.
    entry_cookie, _ = short.new_browser()
    with pytest.raises(OAuthError, match="oauth_connection_invalid"):
        short.touch_browser_session(entry_cookie)
    cookie, session = complete(short, provider, "user-a", begin(short, provider, "user-a"))

    # Immediately after login (< 25% of idle elapsed): throttled, returns None.
    assert short.touch_browser_session(cookie) is None
    now[0] += 700  # past 600s LIFETIME, still < 25% (900s) of 3600s idle
    # Anonymous direct-entry expired at LIFETIME (600s), while authenticated session survives.
    with pytest.raises(OAuthError, match="oauth_connection_invalid"):
        short.browser_session(entry_cookie)
    assert short.browser_session(cookie) == session
    assert short.touch_browser_session(cookie) is None

    # Past 25% of idle (1000s elapsed): touch extends to now + 3600.
    now[0] += 300
    remaining = short.touch_browser_session(cookie)
    assert remaining == 3600

    # Advance past original 3600s idle deadline (4000s total, 3000s since slide): still valid.
    now[0] += 3000
    assert short.browser_session(cookie) == session

    # Slide again near the absolute cap (at t=8800, expires=7600 would be expired, so slide at t=7000 then t=9000).
    assert short.touch_browser_session(cookie) == 3600  # expires at 4000+3600=7600
    now[0] += 3000  # t=7000 (600s left <= 2700s): target=min(10600, 10000)=10000
    remaining = short.touch_browser_session(cookie)
    assert remaining == 3000
    # Once already at absolute_expires, touching again returns None (no redundant writes).
    now[0] += 1500  # t=8500
    assert short.touch_browser_session(cookie) is None
    assert short.browser_session(cookie) == session

    # Past absolute cap (t=10001): hard expiry, both browser_session and touch refuse.
    now[0] += 1501
    with pytest.raises(OAuthError, match="oauth_connection_invalid"):
        short.browser_session(cookie)
    with pytest.raises(OAuthError, match="oauth_connection_invalid"):
        short.touch_browser_session(cookie)


def test_disconnect_invalidates_slid_browser_session(direct, tmp_path, monkeypatch):
    import time as real_time

    manager, provider = direct
    now = [real_time.time()]
    monkeypatch.setattr("signin_window.delegation.time.time", lambda: now[0])
    monkeypatch.setattr("signin_window.direct.time.time", lambda: now[0])
    cfg = replace(manager.config, browser_idle_lifetime=3600, browser_absolute_lifetime=10000)
    short = DirectOAuthManager(cfg, tmp_path / "revoke", required_groups={"example-app"})
    cookie, session = complete(short, provider, "user-a", begin(short, provider, "user-a"))
    now[0] += 1000
    assert short.touch_browser_session(cookie) == 3600
    short.disconnect_browser(cookie, session["csrf"])
    with pytest.raises(OAuthError, match="oauth_connection_invalid"):
        short.touch_browser_session(cookie)


def test_legacy_cookie_without_absolute_expires_is_not_extended(direct, tmp_path, monkeypatch):
    import time as real_time

    manager, provider = direct
    now = [real_time.time()]
    monkeypatch.setattr("signin_window.delegation.time.time", lambda: now[0])
    monkeypatch.setattr("signin_window.direct.time.time", lambda: now[0])
    short = DirectOAuthManager(manager.config, tmp_path / "legacy", required_groups={"example-app"})
    _, session = complete(short, provider, "user-a", begin(short, provider, "user-a"))
    # Insert a legacy pre-upgrade direct-browser capability with no absolute_expires and 600s TTL.
    legacy = short._new_cap(
        "direct-browser", "user-a", {"csrf": session["csrf"], "generation": short.revision("user-a")}
    )
    now[0] += 300
    assert short.browser_session(legacy) == session
    assert short.touch_browser_session(legacy) is None
    now[0] += 301
    with pytest.raises(OAuthError, match="oauth_connection_invalid"):
        short.browser_session(legacy)


def test_repeated_sign_ins_reclaim_superseded_browser_sessions(direct, tmp_path):
    manager, provider = direct
    short = DirectOAuthManager(manager.config, tmp_path / "reclaim", required_groups={"example-app"})
    last = None
    for _ in range(35):
        last = complete(short, provider, "user-a", begin(short, provider, "user-a"))
    cookie, session = last
    short.disconnect_browser(cookie, session["csrf"])
    with short._db() as db:
        remaining = db.execute(
            "SELECT COUNT(*) FROM capabilities WHERE owner=? AND kind='direct-browser'", ("user-a",)
        ).fetchone()[0]
    assert remaining == 0
    reconnected = complete(short, provider, "user-a", begin(short, provider, "user-a"))
    assert reconnected[1]["owner"] == "user-a"


def test_failed_save_preserves_existing_browser_session_on_callback_and_disconnect(direct, tmp_path, monkeypatch):
    manager, provider = direct
    short = DirectOAuthManager(manager.config, tmp_path / "atomic", required_groups={"example-app"})
    cookie, session = complete(short, provider, "user-a", begin(short, provider, "user-a"))
    flow = begin(short, provider, "user-a")
    real_save = short._save

    def fail_save(*args, **kwargs):
        raise RuntimeError("simulated db failure")

    monkeypatch.setattr(short, "_save", fail_save)
    with pytest.raises(OAuthError):
        complete(short, provider, "user-a", flow)
    assert short.browser_session(cookie) == session
    with pytest.raises(RuntimeError, match="simulated db failure"):
        short.disconnect_browser(cookie, session["csrf"])
    assert short.browser_session(cookie) == session
    monkeypatch.setattr(short, "_save", real_save)
    short.disconnect_browser(cookie, session["csrf"])
    with pytest.raises(OAuthError, match="oauth_connection_invalid"):
        short.browser_session(cookie)


def test_failed_disconnect_cleanup_rolls_back_account_so_retry_revokes(direct, tmp_path, monkeypatch):
    from contextlib import contextmanager

    manager, provider = direct
    short = DirectOAuthManager(manager.config, tmp_path / "atomic-cleanup", required_groups={"example-app"})
    cookie, session = complete(short, provider, "user-a", begin(short, provider, "user-a"))
    revoked_before = len(provider.revoked)

    class FailCleanupDB:
        def __init__(self, inner):
            self._inner = inner

        def execute(self, sql, params=()):
            if "DELETE FROM capabilities" in sql:
                raise RuntimeError("simulated cleanup failure")
            return self._inner.execute(sql, params)

    orig_db = short._db

    @contextmanager
    def failing_cleanup_db():
        with orig_db() as db:
            yield FailCleanupDB(db)

    monkeypatch.setattr(short, "_db", failing_cleanup_db)
    with pytest.raises(RuntimeError, match="simulated cleanup failure"):
        short.disconnect_browser(cookie, session["csrf"])
    monkeypatch.setattr(short, "_db", orig_db)
    assert short.connected("user-a")
    assert short.browser_session(cookie) == session
    assert len(provider.revoked) == revoked_before
    # Retry succeeds and revokes the preserved refresh token at the provider.
    short.disconnect_browser(cookie, session["csrf"])
    assert not short.connected("user-a")
    assert len(provider.revoked) > revoked_before


def test_callback_rejects_browser_session_past_absolute_expiry_and_shares_timestamp(direct, tmp_path, monkeypatch):
    import time as real_time

    manager, provider = direct
    base = real_time.time()
    ticks = [0]

    def advancing_clock():
        ticks[0] += 1
        return base + ticks[0] * 0.01

    monkeypatch.setattr("signin_window.delegation.time.time", advancing_clock)
    monkeypatch.setattr("signin_window.direct.time.time", advancing_clock)
    cfg = replace(manager.config, browser_idle_lifetime=3600, browser_absolute_lifetime=3600)
    short = DirectOAuthManager(cfg, tmp_path / "equal-lifetimes", required_groups={"example-app"})
    cookie, session = complete(short, provider, "user-a", begin(short, provider, "user-a"))
    # Even under a clock that advances on every read, DB expires and encrypted absolute_expires match exactly.
    with short._db() as db:
        row = db.execute("SELECT * FROM capabilities WHERE owner=? AND kind='direct-browser'", ("user-a",)).fetchone()
    payload = short._decrypt("direct-browser", "user-a", [row["digest"], row["expires"]], row["encrypted"])
    assert row["expires"] == payload["absolute_expires"]

    # An in-flight callback must reject a session whose encrypted absolute_expires passed even if DB expires has not.
    now = [base + 100.0]
    monkeypatch.setattr("signin_window.delegation.time.time", lambda: now[0])
    monkeypatch.setattr("signin_window.direct.time.time", lambda: now[0])
    flow = begin(short, provider, "user-a", (cookie, session))
    gen_before = short.revision("user-a")
    real_validate = short._validate

    def skew_db_expires_past_abs(*args, **kwargs):
        result = real_validate(*args, **kwargs)
        # Re-encrypt row with DB expires > now while encrypted absolute_expires < now.
        with short._db() as db:
            r = db.execute("SELECT * FROM capabilities WHERE owner=? AND kind='direct-browser'", ("user-a",)).fetchone()
            p = short._decrypt("direct-browser", "user-a", [r["digest"], r["expires"]], r["encrypted"])
            p["absolute_expires"] = now[0] - 1.0
            future_db_exp = now[0] + 600.0
            enc = short._encrypt("direct-browser", "user-a", [r["digest"], future_db_exp], p)
            db.execute(
                "UPDATE capabilities SET expires=?, encrypted=? WHERE digest=?",
                (future_db_exp, enc, r["digest"]),
            )
        return result

    monkeypatch.setattr(short, "_validate", skew_db_expires_past_abs)
    with pytest.raises(OAuthError):
        complete(short, provider, "user-a", flow)
    assert short.revision("user-a") == gen_before


def test_touch_samples_clock_inside_db_transaction(direct, tmp_path, monkeypatch):
    import time as real_time
    from contextlib import contextmanager

    manager, provider = direct
    now = [real_time.time()]
    monkeypatch.setattr("signin_window.delegation.time.time", lambda: now[0])
    monkeypatch.setattr("signin_window.direct.time.time", lambda: now[0])
    cfg = replace(manager.config, browser_idle_lifetime=3600, browser_absolute_lifetime=10000)
    short = DirectOAuthManager(cfg, tmp_path / "txclock", required_groups={"example-app"})
    cookie, _ = complete(short, provider, "user-a", begin(short, provider, "user-a"))
    now[0] += 3599  # 1 second before expiry
    orig_db = short._db
    calls = [0]

    @contextmanager
    def slow_db():
        with orig_db() as db:
            calls[0] += 1
            if calls[0] == 2:
                # Simulate waiting on SQLite lock until after idle expiry.
                now[0] += 5
            yield db

    monkeypatch.setattr(short, "_db", slow_db)
    with pytest.raises(OAuthError, match="oauth_connection_invalid"):
        short.touch_browser_session(cookie)


def test_second_device_sign_in_preserves_existing_browser_session_and_disconnect_revokes_all(direct, tmp_path):
    manager, provider = direct
    short = DirectOAuthManager(manager.config, tmp_path / "multi-device", required_groups={"example-app"})
    laptop_cookie, laptop_session = complete(short, provider, "user-a", begin(short, provider, "user-a"))
    rev_after_first = short.revision("user-a")
    phone_cookie, phone_session = complete(short, provider, "user-a", begin(short, provider, "user-a"))

    assert short.revision("user-a") == rev_after_first
    assert laptop_cookie != phone_cookie
    assert short.browser_session(laptop_cookie) == laptop_session
    assert short.browser_session(phone_cookie) == phone_session
    with short.management_session(laptop_cookie, laptop_session["csrf"]) as active:
        assert active == laptop_session

    # Disconnecting from one device must immediately revoke every device's browser session.
    short.disconnect_browser(phone_cookie, phone_session["csrf"])
    for cookie in (laptop_cookie, phone_cookie):
        with pytest.raises(OAuthError, match="oauth_connection_invalid"):
            short.browser_session(cookie)


def test_multi_device_sessions_enforce_per_owner_cap_without_exhausting_budget(direct, tmp_path):
    manager, provider = direct
    short = DirectOAuthManager(manager.config, tmp_path / "session-cap", required_groups={"example-app"})
    cookies = []
    for _ in range(15):
        cookie, _ = complete(short, provider, "user-a", begin(short, provider, "user-a"))
        cookies.append(cookie)
    with short._db() as db:
        count = db.execute(
            "SELECT COUNT(*) FROM capabilities WHERE owner=? AND kind='direct-browser'", ("user-a",)
        ).fetchone()[0]
    assert count == 10
    # Oldest 5 were evicted; newest 10 remain valid.
    for old in cookies[:5]:
        with pytest.raises(OAuthError, match="oauth_connection_invalid"):
            short.browser_session(old)
    for recent in cookies[5:]:
        assert short.browser_session(recent)["owner"] == "user-a"


def test_reconnect_after_uncertain_status_revokes_prior_device_sessions(direct, tmp_path):
    manager, provider = direct
    short = DirectOAuthManager(manager.config, tmp_path / "uncertain-barrier", required_groups={"example-app"})
    laptop_cookie, _ = complete(short, provider, "user-a", begin(short, provider, "user-a"))

    # Simulate a failed refresh / provider revocation moving the account to uncertain.
    with short._lock("user-a"):
        acct = short._account("user-a")
        grant = short._grant(acct)
        acct.update(generation=str(int(acct["generation"]) + 1), status="uncertain")
        short._save(acct, grant)
    assert not short.connected("user-a")

    # Reconnecting from another device must not revive pre-revocation cookies.
    phone_cookie, phone_session = complete(short, provider, "user-a", begin(short, provider, "user-a"))
    assert short.browser_session(phone_cookie) == phone_session
    with pytest.raises(OAuthError, match="oauth_connection_invalid"):
        short.browser_session(laptop_cookie)


def test_current_identity_prove_split_and_prove_owner_helper(direct):
    manager, provider = direct
    complete(manager, provider, "user-a", begin(manager, provider, "user-a"))
    provider.reads.clear()

    # Default prove=True verifies locally AND calls owner proof on the resource.
    token, claims = manager.current_identity("user-a")
    assert claims["person_id"] == "user-a"
    assert ("POST", RESOURCE) in provider.reads

    # Default prove=True stays fail-closed when resource owner proof disagrees.
    provider.proof_owner = "user-b"
    with pytest.raises(OAuthError):
        manager.current_identity("user-a")

    # prove=False verifies token/claims/groups locally without calling _prove_owner.
    provider.reads.clear()
    local_token, local_claims = manager.current_identity("user-a", prove=False)
    assert local_token == token
    assert local_claims["person_id"] == "user-a"
    assert ("POST", RESOURCE) not in provider.reads

    # prove_owner delegates to _prove_owner and fails closed on mismatch or bad inputs.
    with pytest.raises(OAuthError):
        manager.prove_owner("user-a", local_token)
    provider.proof_owner = None
    manager.prove_owner("user-a", local_token)
    assert ("POST", RESOURCE) in provider.reads
    with pytest.raises(OAuthError):
        manager.prove_owner("user-b", local_token)
    with pytest.raises(OAuthError):
        manager.prove_owner("bad owner!", local_token)
    with pytest.raises(OAuthError):
        manager.prove_owner("user-a", "")
    with pytest.raises(OAuthError):
        manager.prove_owner("user-a", None)

    # Non-bool prove values (e.g. None, 0) fail closed instead of skipping remote proof.
    with pytest.raises(OAuthError):
        manager.current_identity("user-a", prove=None)
    with pytest.raises(OAuthError):
        manager.current_identity("user-a", prove=0)

    # prove=False still fails closed on missing required group or wrong owner claim.
    manager.required_groups = frozenset({"missing-group"})
    with pytest.raises(OAuthError):
        manager.current_identity("user-a", prove=False)
