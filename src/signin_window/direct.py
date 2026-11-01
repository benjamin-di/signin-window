"""Optional single-consent browser entry into the delegated grant store.

The owner is unknown at entry. It is learned only from signed access claims and
the configured resource's authenticated owner proof. An encrypted logical clock
orders starts and owner revocation barriers without relying on wall-clock races.
"""

from __future__ import annotations

import hmac
import secrets
from contextlib import contextmanager

from .delegation import OAuthError, OAuthManager, _hash, _owner


class DirectOAuthManager(OAuthManager):
    """Use the same confidential client, consent, refresh grant and store.

    ``owner_claim`` must be an immutable normalized owner asserted by the issuer;
    ``required_groups`` is an application admission floor. Resource admission is
    rechecked for browser management through ``current_identity``.
    """

    def __init__(self, config, state_dir, *, owner_claim="person_id", required_groups=()):
        if isinstance(required_groups, (str, bytes)):
            raise OAuthError("oauth_configuration_invalid")
        try:
            required_groups = tuple(required_groups)
        except TypeError:
            raise OAuthError("oauth_configuration_invalid") from None
        if (
            not isinstance(owner_claim, str)
            or not owner_claim
            or not all(isinstance(group, str) and group for group in required_groups)
        ):
            raise OAuthError("oauth_configuration_invalid")
        super().__init__(config, state_dir)
        self.owner_claim = owner_claim
        self.required_groups = frozenset(required_groups)
        with self._db() as db:
            db.execute("CREATE TABLE IF NOT EXISTS direct_metadata(key TEXT PRIMARY KEY, encrypted BLOB NOT NULL)")

    def _metadata_value(self, db, key):
        row = db.execute("SELECT encrypted FROM direct_metadata WHERE key=?", (key,)).fetchone()
        if row is None:
            return None
        value = self._decrypt("direct-metadata", key, 1, row[0])
        if not isinstance(value, dict) or set(value) != {"sequence"} or type(value["sequence"]) is not int:
            raise OAuthError()
        if not 0 <= value["sequence"] < 2**63:
            raise OAuthError()
        return value["sequence"]

    def _store_sequence(self, db, key, sequence):
        db.execute(
            "INSERT OR REPLACE INTO direct_metadata VALUES (?,?)",
            (
                key,
                self._encrypt("direct-metadata", key, 1, {"sequence": sequence}),
            ),
        )

    def _advance(self, db):
        sequence = (self._metadata_value(db, "clock") or 0) + 1
        if sequence >= 2**63:
            raise OAuthError()
        self._store_sequence(db, "clock", sequence)
        return sequence

    def _barrier(self, owner):
        with self._db() as db:
            return self._metadata_value(db, "owner:" + owner)

    def _mark_barrier(self, owner):
        with self._db() as db:
            self._store_sequence(db, "owner:" + owner, self._advance(db))

    def _clear(self, account):
        # Called while the inherited per-owner lock is held. Commit the barrier
        # before clearing: even a crash cannot let an older direct flow install.
        self._mark_barrier(account["owner"])
        return super()._clear(account)

    def new_browser(self):
        csrf = secrets.token_urlsafe(32)
        cookie = secrets.token_urlsafe(32)
        self._write_cap("direct-entry", cookie, "browser-" + _hash(cookie), {"csrf": csrf})
        return cookie, {"owner": None, "csrf": csrf}

    def browser_session(self, cookie):
        try:
            owner, session = self._cap("direct-browser", cookie)
        except OAuthError:
            _, session = self._cap("direct-entry", cookie)
            return {"owner": None, "csrf": session["csrf"]}
        if session["generation"] != self.revision(owner) or not self.connected(owner):
            raise OAuthError("oauth_connection_invalid")
        return {"owner": owner, "csrf": session["csrf"]}

    def authorize(self, cookie, csrf):
        session = self.browser_session(cookie)
        if not isinstance(csrf, str) or not hmac.compare_digest(csrf, session["csrf"]):
            raise OAuthError("oauth_connection_invalid")
        with self._db() as db:
            sequence = self._advance(db)
        metadata = self._metadata()
        verifier, nonce = secrets.token_urlsafe(48), secrets.token_urlsafe(32)
        state = self._new_cap(
            "direct-state",
            "browser-" + _hash(cookie),
            {
                "browser": _hash(cookie),
                "owner": session["owner"],
                "sequence": sequence,
                "verifier": verifier,
                "nonce": nonce,
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
        return location

    def _identity(self, token, metadata):
        claims, _ = self._decode(token, self._keys(metadata), self.config.resource, access=True)
        owner = _owner(claims.get(self.owner_claim))
        groups = claims.get("groups", [])
        if (
            claims.get("client_id") != self.config.client_id
            or not isinstance(groups, list)
            or not all(isinstance(group, str) for group in groups)
            or not self.required_groups <= set(groups)
        ):
            raise OAuthError()
        self._prove_owner(owner, token)
        return owner, claims

    def current_identity(self, owner):
        token = self.access_token(owner, 60)
        actual, claims = self._identity(token, self._metadata())
        if actual != owner:
            raise OAuthError()
        return token, claims

    def finish_direct_callback(self, cookie, parameters):
        if not isinstance(parameters, dict):
            raise OAuthError("oauth_connection_invalid")
        _, flow = self._cap("direct-state", parameters.get("state"))
        session = self.browser_session(cookie)
        if not hmac.compare_digest(flow["browser"], _hash(cookie)) or flow["owner"] != session["owner"]:
            raise OAuthError("oauth_connection_invalid")
        self._cap("direct-state", parameters["state"], consume=True)
        code = parameters.get("code")
        if (
            "error" in parameters
            or parameters.get("iss", self.config.issuer) != self.config.issuer
            or not isinstance(code, str)
            or not 1 <= len(code) <= 4096
            or any(c.isspace() for c in code)
        ):
            raise OAuthError("oauth_connection_invalid")
        token = None
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
            owner, _ = self._identity(token["access_token"], flow["metadata"])
            if flow["owner"] is not None and flow["owner"] != owner:
                raise OAuthError()
            with self._lock(owner):
                account = self._account(owner)
                barrier = self._barrier(owner)
                # A nonempty account without authenticated direct metadata must
                # never silently adopt an unknown preexisting generation.
                if (
                    (barrier is None and account["generation"] != "0")
                    or (barrier is not None and flow["sequence"] <= barrier)
                    or (account["subject"] and account["subject"] != grant["subject"])
                ):
                    raise OAuthError()
                account.update(
                    subject=grant["subject"], generation=str(int(account["generation"]) + 1), status="connected"
                )
                csrf = secrets.token_urlsafe(32)
                authenticated = self._new_cap(
                    "direct-browser",
                    owner,
                    {
                        "csrf": csrf,
                        "generation": account["generation"],
                    },
                )
                kind = "direct-browser" if session["owner"] is not None else "direct-entry"
                self._cap(kind, cookie, consume=True)
                self._mark_barrier(owner)
                self._save(account, grant)
                return authenticated, {"owner": owner, "csrf": csrf}
        except Exception:
            if token is not None:
                self._revoke(token)
            raise OAuthError() from None

    @contextmanager
    def management_session(self, cookie, csrf):
        """Serialize a final local control mutation with grant replacement/revocation.

        Verify live provider membership before entering. Do not call OAuth/network
        methods while holding this guard; grant refresh uses the same owner lock.
        """
        session = self.browser_session(cookie)
        if session["owner"] is None or not isinstance(csrf, str) or not hmac.compare_digest(csrf, session["csrf"]):
            raise OAuthError("oauth_connection_invalid")
        with self._lock(session["owner"]):
            current = self.browser_session(cookie)
            if current != session:
                raise OAuthError("oauth_connection_invalid")
            yield current

    def disconnect_browser(self, cookie, csrf):
        with self.management_session(cookie, csrf) as session:
            revoke = self._clear(self._account(session["owner"]))
        self._revoke(revoke)
