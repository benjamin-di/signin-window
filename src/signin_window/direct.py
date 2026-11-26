"""Optional single-consent browser entry into the delegated grant store.

The owner is unknown at entry. It is learned only from signed access claims and
the configured resource's authenticated owner proof. An encrypted logical clock
orders starts and owner revocation barriers without relying on wall-clock races.
"""

from __future__ import annotations

import hmac
import re
import secrets
import time
from contextlib import contextmanager

from .delegation import OAuthError, OAuthManager, _hash, _owner

MAX_BROWSER_SESSIONS = 10


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

    def _session_epoch(self, owner, *, db=None):
        if db is not None:
            return self._metadata_value(db, "session-epoch:" + owner) or 0
        with self._db() as conn:
            return self._metadata_value(conn, "session-epoch:" + owner) or 0

    def _session_epoch_matches(self, owner, session, *, db=None):
        if "session_epoch" in session:
            return type(session["session_epoch"]) is int and session["session_epoch"] == self._session_epoch(
                owner, db=db
            )
        return session.get("generation") == self.revision(owner)

    def _clear(self, account):
        # Called while the inherited per-owner lock is held. Commit the barrier,
        # disconnected account, and capability cleanup atomically so a failed
        # cleanup leaves the grant available for retry and provider revocation.
        try:
            token = self._grant(account).get("token") if account["encrypted"] else None
        except OAuthError:
            token = None
        account.update(generation=str(int(account["generation"]) + 1), status="disconnected")
        with self._db() as db:
            self._store_sequence(db, "owner:" + account["owner"], self._advance(db))
            self._store_sequence(db, "session-epoch:" + account["owner"], self._advance(db))
            self._save(account, db=db)
            db.execute(
                "DELETE FROM capabilities WHERE owner=? AND kind IN ('state', 'direct-browser')",
                (account["owner"],),
            )
        return token

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
        absolute_expires = session.get("absolute_expires")
        if (
            not self._session_epoch_matches(owner, session)
            or not self.connected(owner)
            or (absolute_expires is not None and absolute_expires <= time.time())
        ):
            raise OAuthError("oauth_connection_invalid")
        return {"owner": owner, "csrf": session["csrf"]}

    def touch_browser_session(self, cookie):
        """Extend a valid authenticated browser session's idle expiry up to its absolute cap.

        Returns the new remaining lifetime in seconds when extended, or ``None``
        when no refresh is needed yet. Raises ``OAuthError`` for invalid,
        expired, unauthenticated or revoked cookies.
        """
        if not isinstance(cookie, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", cookie):
            raise OAuthError("oauth_connection_invalid")
        digest = _hash("direct-browser:" + cookie)
        with self._db() as db:
            now = time.time()
            row = db.execute(
                "SELECT owner, expires FROM capabilities WHERE digest=? AND kind='direct-browser'", (digest,)
            ).fetchone()
            if not row or row["expires"] <= now:
                raise OAuthError("oauth_connection_invalid")
            owner = row["owner"]
        with self._lock(owner):
            with self._db() as db:
                now = time.time()
                row = db.execute(
                    "SELECT * FROM capabilities WHERE digest=? AND kind='direct-browser'", (digest,)
                ).fetchone()
                if not row or row["expires"] <= now:
                    raise OAuthError("oauth_connection_invalid")
                session = self._decrypt("direct-browser", owner, [digest, row["expires"]], row["encrypted"])
                absolute_expires = session.get("absolute_expires")
                if (
                    not self._session_epoch_matches(owner, session, db=db)
                    or not self.connected(owner)
                    or (absolute_expires is not None and absolute_expires <= now)
                ):
                    raise OAuthError("oauth_connection_invalid")
                if absolute_expires is None:
                    return None
                idle = self.config.browser_idle_lifetime
                target = min(now + idle, absolute_expires)
                if row["expires"] - now > idle * 0.75 or target <= row["expires"]:
                    return None
                db.execute(
                    "UPDATE capabilities SET expires=?, encrypted=? WHERE digest=? AND kind='direct-browser'",
                    (target, self._encrypt("direct-browser", owner, [digest, target], session), digest),
                )
            return max(1, int(target - now))

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
                was_connected = account["status"] == "connected"
                account.update(
                    subject=grant["subject"], generation=str(int(account["generation"]) + 1), status="connected"
                )
                csrf = secrets.token_urlsafe(32)
                kind = "direct-browser" if session["owner"] is not None else "direct-entry"
                incoming_digest = _hash(kind + ":" + cookie)
                with self._db() as db:
                    now = time.time()
                    incoming_row = db.execute(
                        "SELECT * FROM capabilities WHERE digest=? AND kind=?",
                        (incoming_digest, kind),
                    ).fetchone()
                    if not incoming_row or incoming_row["expires"] <= now:
                        raise OAuthError("oauth_connection_invalid")
                    incoming_payload = self._decrypt(
                        kind,
                        incoming_row["owner"],
                        [incoming_digest, incoming_row["expires"]],
                        incoming_row["encrypted"],
                    )
                    if kind == "direct-browser":
                        incoming_abs = incoming_payload.get("absolute_expires")
                        if incoming_abs is not None and incoming_abs <= now:
                            raise OAuthError("oauth_connection_invalid")
                    db.execute("DELETE FROM capabilities WHERE digest=? AND kind=?", (incoming_digest, kind))
                    if not was_connected:
                        self._store_sequence(db, "session-epoch:" + owner, self._advance(db))
                        db.execute("DELETE FROM capabilities WHERE owner=? AND kind='direct-browser'", (owner,))
                    else:
                        db.execute(
                            "DELETE FROM capabilities WHERE owner=? AND kind='direct-browser' AND expires<=?",
                            (owner, now),
                        )
                        existing = db.execute(
                            "SELECT digest FROM capabilities WHERE owner=? AND kind='direct-browser' "
                            "ORDER BY expires DESC, rowid DESC",
                            (owner,),
                        ).fetchall()
                        for stale in existing[MAX_BROWSER_SESSIONS - 1 :]:
                            db.execute("DELETE FROM capabilities WHERE digest=?", (stale["digest"],))
                    authenticated = self._new_cap(
                        "direct-browser",
                        owner,
                        {
                            "csrf": csrf,
                            "generation": account["generation"],
                            "session_epoch": self._session_epoch(owner, db=db),
                            "absolute_expires": now + self.config.browser_absolute_lifetime,
                        },
                        lifetime=self.config.browser_idle_lifetime,
                        db=db,
                        now=now,
                    )
                    self._store_sequence(db, "owner:" + owner, self._advance(db))
                    self._save(account, grant, db=db)
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
