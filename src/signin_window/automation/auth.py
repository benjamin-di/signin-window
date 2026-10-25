"""Shared authentication contracts; applications still verify their own access."""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Protocol

from pydantic import model_validator

from ._models import FrozenModel

AuthBrowserSession = Any


class SecretFiller(Protocol):
    def fill(
        self,
        browser: Any,
        *,
        secret_ref: str,
        field: str,
        selectors: tuple[str, ...],
        allowed_origins: frozenset[str],
        all_visible: bool = False,
    ) -> None: ...


class AuthFailureBase(RuntimeError):
    """Common base for typed, redacted authentication failures."""


class SecretDeliveryError(RuntimeError):
    """An origin-scoped credential could not be delivered."""


class AuthOutcome(StrEnum):
    VERIFIED = "verified"
    CREDENTIAL_REJECTED = "credential_rejected"
    SECOND_FACTOR_REQUIRED = "second_factor_required"
    ACCOUNT_ALERT = "account_alert"
    CHALLENGE_BLOCKED = "challenge_blocked"
    UNKNOWN_FLOW = "unknown_flow"
    TIMEOUT = "timeout"
    INFRASTRUCTURE_ERROR = "infrastructure_error"


class CredentialAction(StrEnum):
    """The strongest provider-owned credential action actually observed."""

    NONE = "none"
    PASSWORD_SUBMIT = "password_submit"  # noqa: S105 - closed protocol vocabulary
    GOOGLE_PASSWORD_SUBMIT = "google_password_submit"  # noqa: S105 - closed protocol vocabulary
    GOOGLE_PASSWORD_AUTO_SUBMIT = "google_password_auto_submit"  # noqa: S105 - closed protocol vocabulary
    GOOGLE_TOTP_SUBMIT = "google_totp_submit"


class AuthObservationSpec(FrozenModel):
    any_selectors: tuple[str, ...] = ()
    # Evidence that a control is not merely on the page but usable: visible,
    # enabled, and not read-only. `any_selectors` tests geometry and CSS only,
    # which cannot tell a live field from a read-only decoy — and a decoy is
    # exactly what a two-step login renders for the step you are not on. A
    # credential step selected by `any_selectors` therefore promises something
    # `fill` cannot honour, and `fill` then blocks until it times out.
    editable_selectors: tuple[str, ...] = ()
    any_text: tuple[str, ...] = ()
    any_path_contains: tuple[str, ...] = ()
    required_selectors: tuple[str, ...] = ()
    required_text: tuple[str, ...] = ()
    required_hosts: tuple[str, ...] = ()
    required_host_suffixes: tuple[str, ...] = ()
    excluded_hosts: tuple[str, ...] = ()
    excluded_path_prefixes: tuple[str, ...] = ()
    absent_selectors: tuple[str, ...] = ()

    @model_validator(mode="after")
    def require_predicate(self) -> AuthObservationSpec:
        if not any(self.model_dump(mode="python").values()):
            raise ValueError("auth observation must contain evidence")
        fields = self.model_dump(mode="python")
        if any(not value.strip() for values in fields.values() for value in values):
            raise ValueError("auth observation evidence cannot be blank")
        hosts = self.required_hosts + self.required_host_suffixes + self.excluded_hosts
        if any(host != host.lower() or "://" in host for host in hosts):
            raise ValueError("auth observation hosts must be lowercase hostnames")
        if any(not prefix.startswith("/") for prefix in self.excluded_path_prefixes):
            raise ValueError("excluded auth paths must begin with a slash")
        return self


class AuthPhase(StrEnum):
    PROFILE = "profile"
    ENTRY = "entry"
    USERNAME = "username"
    PASSWORD = "password"  # noqa: S105 - closed protocol vocabulary
    CHALLENGE = "challenge"
    CALLBACK = "callback"
    VERIFICATION = "verification"
    UNKNOWN = "unknown"


class AuthEvidenceFamily(StrEnum):
    NONE = "none"
    SELECTOR = "selector"
    TEXT = "text"
    PATH = "path"
    HOST_CLASS = "host_class"
    COOKIE_PRESENCE = "cookie_presence"
    CALLBACK_STATUS = "callback_status"
    ASSESSMENT = "assessment"


class RouteClass(StrEnum):
    PUBLISHER_AUTH = "publisher_auth"
    PUBLISHER_CONTENT = "publisher_content"
    KNOWN_IDP = "known_idp"
    KNOWN_CHALLENGE_VENDOR = "known_challenge_vendor"
    OTHER = "other"


class IdentityExitReason(StrEnum):
    """Why an identity flow stopped, which its other facts cannot express.

    A page that closed on its own and one whose context was destroyed both
    report ``identity_page_closed``, yet only the second is an ambiguous
    post-submit state. ``DECLINED`` belongs to a cached-callback replay that
    refused to proceed rather than resubmit a credential; the credential flow
    itself never exits that way.
    """

    CALLBACK_COMPLETE = "callback_complete"
    IDENTITY_PAGE_CLOSED = "identity_page_closed"
    IDENTITY_CONTEXT_CLOSED = "identity_context_closed"
    DECLINED = "declined"


class PasskeyMode(StrEnum):
    """Provider-selected behavior for an empty virtual authenticator."""

    EMPTY_PRESENT = "empty_present"
    NON_PRESENT = "non_present"


class AuthFailureStage(StrEnum):
    CREDENTIAL = "credential"
    CALLBACK = "callback"


class AuthFailureCategory(StrEnum):
    CONTROL_MISSING = "control_missing"
    CREDENTIAL_REJECTED = "credential_rejected"
    SECOND_FACTOR_REQUIRED = "second_factor_required"
    ACCOUNT_ALERT = "account_alert"
    CALLBACK_NOT_CONFIRMED = "callback_not_confirmed"
    TIMEOUT = "timeout"
    INFRASTRUCTURE = "infrastructure"
    UNKNOWN = "unknown"


class AuthFailureEvidence(FrozenModel):
    stage: AuthFailureStage
    category: AuthFailureCategory

    @property
    def reason_code(self) -> str:
        return f"{self.stage.value}_{self.category.value}"


class AuthFlowFailure(AuthFailureBase):
    def __init__(self, outcome: AuthOutcome, evidence: AuthFailureEvidence) -> None:
        self.outcome, self.evidence = outcome, evidence
        super().__init__(evidence.reason_code)
