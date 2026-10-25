"""Bounded Google identity drive with no publisher-session authority."""

from __future__ import annotations

import time
from collections.abc import Callable
from contextlib import nullcontext, suppress
from dataclasses import dataclass
from enum import StrEnum
from urllib.parse import urlsplit

from pydantic import Field, ValidationError, model_validator

from ._models import FrozenModel
from .auth import (
    AuthBrowserSession,
    AuthFailureBase,
    AuthObservationSpec,
    AuthPhase,
    CredentialAction,
    IdentityExitReason,
    PasskeyMode,
    SecretFiller,
)
from .auth import (
    AuthFailureCategory as MintFailureCategory,
)
from .auth import (
    AuthFailureEvidence as MintFailureEvidence,
)
from .auth import (
    AuthFailureStage as MintFailureStage,
)
from .auth import (
    AuthFlowFailure as AcquisitionFailure,
)
from .auth import (
    AuthOutcome as MintOutcome,
)
from .auth import (
    SecretDeliveryError as LoginInfrastructureError,
)
from .auth_ui import AuthSelectorEvaluationError, build_auth_observation_script, observe_auth_ui

_CONTROL_NAMES = frozenset(
    {
        "account_choices",
        "alternate",
        "consent",
        "email",
        "email_submit",
        "password",
        "password_choice",
        "password_submit",
        "totp",
        "totp_choice",
        "totp_submit",
        "use_another",
    }
)
_ACTION_STRENGTH = {
    CredentialAction.NONE: 0,
    CredentialAction.GOOGLE_PASSWORD_AUTO_SUBMIT: 1,
    CredentialAction.GOOGLE_PASSWORD_SUBMIT: 2,
    CredentialAction.GOOGLE_TOTP_SUBMIT: 3,
}


class GoogleIdentityObservation(FrozenModel):
    email_visible: bool = False
    password_visible: bool = False
    totp_visible: bool = False
    account_chooser: bool = False
    alternate_visible: bool = False
    password_choice: bool = False
    totp_choice: bool = False
    consent_visible: bool = False
    credential_rejected: bool = False
    account_alert: bool = False
    unsupported_second_factor: bool = False


class GoogleIdentityStep(StrEnum):
    ACCOUNT_CHOOSER = "account_chooser"
    EMAIL = "email"
    PASSWORD = "password"  # noqa: S105 - closed protocol vocabulary
    TOTP = "totp"
    TOTP_CHOICE = "totp_choice"
    PASSWORD_CHOICE = "password_choice"  # noqa: S105 - closed protocol vocabulary
    ALTERNATE = "alternate"
    CONSENT = "consent"
    IDLE = "idle"


class GoogleLoopDirective(StrEnum):
    SETTLE = "settle"
    REPOLL = "repoll"


class _SubmitAttempt(StrEnum):
    NOT_FOUND = "not_found"
    SUBMITTED = "submitted"
    AMBIGUOUS_TRANSITION = "ambiguous_transition"


class GoogleIdentityConfig(FrozenModel):
    provider_key: str = Field(min_length=1)
    controls: dict[str, tuple[str, ...]]
    observations: dict[str, AuthObservationSpec]
    secret_ref: str = Field(min_length=1)
    allowed_origins: frozenset[str] = Field(min_length=1)
    identity_hosts: tuple[str, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_google_surface(self) -> GoogleIdentityConfig:
        if set(self.controls) != _CONTROL_NAMES:
            raise ValueError("Google identity controls do not match the driver contract")
        if set(self.observations) != set(GoogleIdentityObservation.model_fields):
            raise ValueError("Google identity observations do not match the driver contract")
        if any(
            not selectors or any(not selector.strip() for selector in selectors) for selectors in self.controls.values()
        ):
            raise ValueError("Google identity controls cannot be empty")
        return self

    def control(self, name: str) -> tuple[str, ...]:
        return self.controls[name]


class GoogleIdentityResult(FrozenModel):
    credential_action: CredentialAction
    callback_complete: bool
    identity_page_closed: bool
    exit_reason: IdentityExitReason


@dataclass(slots=True)
class _GoogleDriveState:
    deadline: float
    chooser_used: bool = False
    email_used: bool = False
    email_transition_deadline: float = 0.0
    password_used: bool = False
    password_redriven: bool = False
    password_fallback_used: bool = False
    password_choice_used: bool = False
    password_transition_deadline: float = 0.0
    totp_used: bool = False
    totp_codes_used: int = 0
    totp_submit_ambiguous: bool = False
    totp_choice_used: bool = False
    totp_choice_clicks: int = 0
    totp_transition_deadline: float = 0.0
    alternate_uses: int = 0
    alternate_transition_deadline: float = 0.0
    consent_used: bool = False
    action: CredentialAction = CredentialAction.NONE


def google_identity_step(
    observation: GoogleIdentityObservation,
) -> GoogleIdentityStep:
    if observation.account_chooser:
        return GoogleIdentityStep.ACCOUNT_CHOOSER
    if observation.email_visible:
        return GoogleIdentityStep.EMAIL
    if observation.password_visible:
        return GoogleIdentityStep.PASSWORD
    if observation.totp_visible:
        return GoogleIdentityStep.TOTP
    if observation.totp_choice:
        return GoogleIdentityStep.TOTP_CHOICE
    if observation.password_choice:
        return GoogleIdentityStep.PASSWORD_CHOICE
    if observation.alternate_visible:
        return GoogleIdentityStep.ALTERNATE
    if observation.consent_visible:
        return GoogleIdentityStep.CONSENT
    return GoogleIdentityStep.IDLE


class GoogleIdentityDriver:
    """Drive one Google popup without deciding publisher callback or session truth."""

    def __init__(
        self,
        config: GoogleIdentityConfig,
        *,
        secrets: SecretFiller,
        clock: Callable[[], float] | None = None,
        step: Callable | None = None,
    ) -> None:
        self.config = config
        self._step = step or (lambda name: nullcontext())
        self._secrets = secrets
        self._clock = clock or time.monotonic
        self._observe_script = build_auth_observation_script(config.observations)
        self._auth_hosts = tuple(sorted({urlsplit(origin).hostname or "" for origin in config.allowed_origins}))

    def drive(
        self,
        browser: AuthBrowserSession,
        *,
        callback_complete: Callable[[], bool],
        resolve_challenge: Callable[[AuthBrowserSession], None],
    ) -> GoogleIdentityResult:
        self._prepare_browser(browser)
        state = _GoogleDriveState(deadline=self._clock() + 180)
        while self._clock() < state.deadline:
            if callback_complete():
                return self._result(
                    state,
                    callback_complete=True,
                    identity_page_closed=self._page_closed(browser),
                    exit_reason=IdentityExitReason.CALLBACK_COMPLETE,
                )
            if self._page_closed(browser):
                return self._result(
                    state,
                    callback_complete=callback_complete(),
                    identity_page_closed=True,
                    exit_reason=IdentityExitReason.IDENTITY_PAGE_CLOSED,
                )
            try:
                resolve_challenge(browser)
                observation = self._observe(browser, AuthPhase.ENTRY)
                self._terminal(observation)
                directive = self._dispatch_step(
                    browser,
                    callback_complete=callback_complete,
                    observation=observation,
                    step=google_identity_step(observation),
                    state=state,
                )
                if directive is GoogleLoopDirective.REPOLL:
                    continue
                browser.wait(0.4)
            except Exception as error:
                if not self._closed_handoff(error, browser, totp_submitted=state.totp_used):
                    raise
                # GIS may replace its document after accepting the code while
                # its popup still reports open. Stop driving identity controls;
                # the publisher must independently settle and prove paid access.
                return self._result(
                    state,
                    callback_complete=callback_complete(),
                    identity_page_closed=(self._target_closed(error) or self._page_closed(browser)),
                    exit_reason=IdentityExitReason.IDENTITY_CONTEXT_CLOSED,
                )
        raise _failure(
            MintOutcome.TIMEOUT,
            MintFailureStage.CALLBACK,
            MintFailureCategory.TIMEOUT,
        )

    def resume_cached_callback(
        self,
        browser: AuthBrowserSession,
        *,
        callback_complete: Callable[[], bool],
        resolve_challenge: Callable[[AuthBrowserSession], None],
    ) -> IdentityExitReason:
        """Replay cached identity state; publisher callback proof remains external.

        The returned reason names how the replay ended. Only
        ``CALLBACK_COMPLETE`` asserts that the publisher predicate fired; the
        closure reasons mean the surface went away with the outcome unknown, and
        ``DECLINED`` means the replay refused rather than resubmit a credential.
        """

        self._prepare_browser(browser)
        deadline = self._clock() + 40
        consent_used = False
        chooser_used = False
        while self._clock() < deadline:
            if callback_complete():
                return IdentityExitReason.CALLBACK_COMPLETE
            if self._page_closed(browser):
                return IdentityExitReason.IDENTITY_PAGE_CLOSED
            try:
                resolve_challenge(browser)
                observation = self._observe(browser, AuthPhase.CALLBACK)
            except Exception as error:
                return self._replay_failure_reason(error)
            self._terminal(observation)
            if observation.account_chooser:
                # A second GIS popup normally opens on the chooser once a
                # Google session exists, so refusing it strands every replay.
                # Selecting the exact cached account reads only the username
                # reference; resubmitting a password or TOTP code stays
                # forbidden by the credential-control branch below.
                if chooser_used:
                    return IdentityExitReason.DECLINED
                try:
                    selected = self._click_cached_account(browser)
                except LoginInfrastructureError:
                    # The flow read this same reference moments ago, so a secret
                    # or origin fault now is a real local condition. Surface it
                    # instead of hiding it behind a declined replay.
                    raise
                except Exception as error:
                    # Selecting the account is what navigates the popup, so a
                    # destroyed context here means the selection may well have
                    # landed: end the replay and let the external publisher proof
                    # decide. Reporting a local infrastructure fault instead
                    # would misdirect the operator and skip the paid probe. Any
                    # other selection error is an ordinary declined replay.
                    return self._replay_failure_reason(error)
                if not selected:
                    return IdentityExitReason.DECLINED
                chooser_used = True
            elif observation.consent_visible:
                if consent_used:
                    return IdentityExitReason.DECLINED
                try:
                    submitted = self._locator_optional(browser, self.config.control("consent"))
                except Exception:
                    submitted = True
                if not submitted:
                    return IdentityExitReason.DECLINED
                consent_used = True
            elif any(
                (
                    observation.email_visible,
                    observation.password_visible,
                    observation.totp_visible,
                    observation.password_choice,
                    observation.totp_choice,
                    observation.alternate_visible,
                )
            ):
                return IdentityExitReason.DECLINED
            try:
                browser.wait(0.4)
            except Exception as error:
                return self._replay_failure_reason(error)
        if callback_complete():
            return IdentityExitReason.CALLBACK_COMPLETE
        return IdentityExitReason.DECLINED

    @classmethod
    def _replay_failure_reason(cls, error: BaseException) -> IdentityExitReason:
        """Classify a replay exception as a lost surface or a declined replay."""

        if cls._target_closed(error) or cls._context_replaced(error):
            return IdentityExitReason.IDENTITY_CONTEXT_CLOSED
        return IdentityExitReason.DECLINED

    def _dispatch_step(
        self,
        browser: AuthBrowserSession,
        *,
        callback_complete: Callable[[], bool],
        observation: GoogleIdentityObservation,
        step: GoogleIdentityStep,
        state: _GoogleDriveState,
    ) -> GoogleLoopDirective:
        if step is GoogleIdentityStep.ACCOUNT_CHOOSER:
            return self._handle_account_chooser(browser, state)
        if step is GoogleIdentityStep.EMAIL:
            return self._handle_email(browser, state)
        if step is GoogleIdentityStep.PASSWORD:
            return self._handle_password(
                browser,
                callback_complete=callback_complete,
                observation=observation,
                state=state,
            )
        if step is GoogleIdentityStep.TOTP:
            return self._handle_totp(browser, state)
        if step is GoogleIdentityStep.TOTP_CHOICE:
            return self._handle_totp_choice(browser, state)
        if step is GoogleIdentityStep.PASSWORD_CHOICE:
            return self._handle_password_choice(browser, state)
        if step is GoogleIdentityStep.ALTERNATE:
            return self._handle_alternate(browser, state)
        if step is GoogleIdentityStep.CONSENT:
            return self._handle_consent(
                browser,
                callback_complete=callback_complete,
                observation=observation,
                state=state,
            )
        return GoogleLoopDirective.SETTLE

    def _handle_account_chooser(
        self,
        browser: AuthBrowserSession,
        state: _GoogleDriveState,
    ) -> GoogleLoopDirective:
        if state.chooser_used:
            browser.wait(0.5)
            return GoogleLoopDirective.REPOLL
        matched = self._click_cached_account(browser)
        if not matched and not self._locator_optional(browser, self.config.control("use_another")):
            raise _failure(
                MintOutcome.UNKNOWN_FLOW,
                MintFailureStage.CREDENTIAL,
                MintFailureCategory.CONTROL_MISSING,
            )
        state.chooser_used = True
        return GoogleLoopDirective.SETTLE

    def _handle_email(
        self,
        browser: AuthBrowserSession,
        state: _GoogleDriveState,
    ) -> GoogleLoopDirective:
        if state.email_used:
            if self._clock() < state.email_transition_deadline:
                browser.wait(0.5)
                return GoogleLoopDirective.REPOLL
            raise _failure(
                MintOutcome.UNKNOWN_FLOW,
                MintFailureStage.CREDENTIAL,
                MintFailureCategory.UNKNOWN,
            )
        with self._step("username"):
            self._secrets.fill(
                browser,
                secret_ref=self.config.secret_ref,
                field="username",
                selectors=self.config.control("email"),
                allowed_origins=self.config.allowed_origins,
            )
            if not self._locator_optional(browser, self.config.control("email_submit")):
                raise _failure(
                    MintOutcome.UNKNOWN_FLOW,
                    MintFailureStage.CREDENTIAL,
                    MintFailureCategory.CONTROL_MISSING,
                )
        state.email_used = True
        state.email_transition_deadline = self._clock() + 10
        return GoogleLoopDirective.SETTLE

    def _handle_password(
        self,
        browser: AuthBrowserSession,
        *,
        callback_complete: Callable[[], bool],
        observation: GoogleIdentityObservation,
        state: _GoogleDriveState,
    ) -> GoogleLoopDirective:
        if not state.password_used:
            with self._step("password"):
                self._secrets.fill(
                    browser,
                    secret_ref=self.config.secret_ref,
                    field="password",
                    selectors=self.config.control("password"),
                    allowed_origins=self.config.allowed_origins,
                )
                state.password_used = True
                if callback_complete() or browser.page.is_closed():
                    self._record_action(state, CredentialAction.GOOGLE_PASSWORD_AUTO_SUBMIT)
                    return GoogleLoopDirective.REPOLL
                try:
                    if not self._locator_optional(browser, self.config.control("password_submit")):
                        raise RuntimeError("password submit control unavailable")
                except RuntimeError:
                    self._record_action(state, CredentialAction.GOOGLE_PASSWORD_AUTO_SUBMIT)
                    return GoogleLoopDirective.REPOLL
                self._record_action(state, CredentialAction.GOOGLE_PASSWORD_SUBMIT)
                state.password_transition_deadline = self._clock() + 10
                return GoogleLoopDirective.SETTLE
        if not state.password_redriven:
            if self._clock() < state.password_transition_deadline:
                browser.wait(0.5)
                return GoogleLoopDirective.REPOLL
            if (
                observation.alternate_visible
                and not state.password_fallback_used
                and self._passkey_alternative_optional(browser, self.config.control("alternate"))
            ):
                state.password_fallback_used = True
                state.alternate_uses = 1
                state.alternate_transition_deadline = self._clock() + 10
                state.password_transition_deadline = self._clock() + 10
                browser.wait(0.4)
                return GoogleLoopDirective.REPOLL
            with self._step("password"):
                if state.password_fallback_used and state.password_choice_used:
                    self._secrets.fill(
                        browser,
                        secret_ref=self.config.secret_ref,
                        field="password",
                        selectors=self.config.control("password"),
                        allowed_origins=self.config.allowed_origins,
                    )
                if not self._locator_optional(browser, self.config.control("password_submit")):
                    raise _failure(
                        MintOutcome.UNKNOWN_FLOW,
                        MintFailureStage.CREDENTIAL,
                        MintFailureCategory.CONTROL_MISSING,
                    )
                state.password_redriven = True
                state.password_transition_deadline = self._clock() + 10
                self._record_action(state, CredentialAction.GOOGLE_PASSWORD_SUBMIT)
                return GoogleLoopDirective.SETTLE
        if self._clock() < state.password_transition_deadline:
            browser.wait(0.5)
            return GoogleLoopDirective.REPOLL
        if (
            observation.alternate_visible
            and state.alternate_uses == 1
            and self._passkey_alternative_optional(browser, self.config.control("alternate"))
        ):
            state.alternate_uses = 2
            state.alternate_transition_deadline = self._clock() + 10
            browser.wait(0.4)
            return GoogleLoopDirective.REPOLL
        raise _failure(
            MintOutcome.UNKNOWN_FLOW,
            MintFailureStage.CREDENTIAL,
            MintFailureCategory.UNKNOWN,
        )

    def _handle_totp(
        self,
        browser: AuthBrowserSession,
        state: _GoogleDriveState,
    ) -> GoogleLoopDirective:
        if state.totp_used:
            if self._clock() < state.totp_transition_deadline:
                browser.wait(0.5)
                return GoogleLoopDirective.REPOLL
            if state.totp_submit_ambiguous:
                raise _failure(
                    MintOutcome.UNKNOWN_FLOW,
                    MintFailureStage.CALLBACK,
                    MintFailureCategory.CALLBACK_NOT_CONFIRMED,
                )
            if state.totp_codes_used >= 2:
                raise _failure(
                    MintOutcome.TIMEOUT,
                    MintFailureStage.CALLBACK,
                    MintFailureCategory.TIMEOUT,
                )
        with self._step("second_factor"):
            capture = getattr(browser, "capture_diagnostic_screenshot", None)
            if callable(capture):
                with suppress(Exception):
                    capture(f"identity-factor-ready-{state.totp_codes_used + 1}")
            self._secrets.fill(
                browser,
                secret_ref=self.config.secret_ref,
                field="totp",
                selectors=self.config.control("totp"),
                allowed_origins=self.config.allowed_origins,
            )
            submit = self._totp_submit(browser, self.config.control("totp_submit"))
            if submit is _SubmitAttempt.NOT_FOUND:
                browser.press(self.config.control("totp"), "Enter")
        state.totp_used = True
        state.totp_codes_used += 1
        state.totp_submit_ambiguous = submit is _SubmitAttempt.AMBIGUOUS_TRANSITION
        state.totp_transition_deadline = self._clock() + 30
        self._record_action(state, CredentialAction.GOOGLE_TOTP_SUBMIT)
        return GoogleLoopDirective.SETTLE

    def _handle_totp_choice(
        self,
        browser: AuthBrowserSession,
        state: _GoogleDriveState,
    ) -> GoogleLoopDirective:
        if state.totp_choice_used:
            if self._clock() < state.totp_transition_deadline:
                browser.wait(0.5)
                return GoogleLoopDirective.REPOLL
            if state.totp_choice_clicks >= 2:
                raise _failure(
                    MintOutcome.SECOND_FACTOR_REQUIRED,
                    MintFailureStage.CREDENTIAL,
                    MintFailureCategory.SECOND_FACTOR_REQUIRED,
                )
        if not self._authenticator_text_optional(browser) and not self._locator_optional(
            browser, self.config.control("totp_choice")
        ):
            raise _failure(
                MintOutcome.SECOND_FACTOR_REQUIRED,
                MintFailureStage.CREDENTIAL,
                MintFailureCategory.SECOND_FACTOR_REQUIRED,
            )
        state.totp_choice_used = True
        state.totp_choice_clicks += 1
        state.totp_transition_deadline = self._clock() + 10
        return GoogleLoopDirective.SETTLE

    def _handle_password_choice(
        self,
        browser: AuthBrowserSession,
        state: _GoogleDriveState,
    ) -> GoogleLoopDirective:
        if state.password_choice_used:
            if self._clock() < state.password_transition_deadline:
                browser.wait(0.5)
                return GoogleLoopDirective.REPOLL
            raise _failure(
                MintOutcome.UNKNOWN_FLOW,
                MintFailureStage.CREDENTIAL,
                MintFailureCategory.CONTROL_MISSING,
            )
        if not self._locator_optional(browser, self.config.control("password_choice")):
            raise _failure(
                MintOutcome.UNKNOWN_FLOW,
                MintFailureStage.CREDENTIAL,
                MintFailureCategory.CONTROL_MISSING,
            )
        if state.password_used and state.password_fallback_used:
            state.password_choice_used = True
            state.password_transition_deadline = self._clock() + 10
        return GoogleLoopDirective.SETTLE

    def _handle_alternate(
        self,
        browser: AuthBrowserSession,
        state: _GoogleDriveState,
    ) -> GoogleLoopDirective:
        second_phase = state.alternate_uses == 1 and state.password_redriven
        post_totp_phase = state.totp_used and state.alternate_uses < 3
        if state.alternate_uses and not second_phase and not post_totp_phase:
            if self._clock() < state.alternate_transition_deadline:
                browser.wait(0.5)
                return GoogleLoopDirective.REPOLL
            raise _failure(
                MintOutcome.SECOND_FACTOR_REQUIRED,
                MintFailureStage.CREDENTIAL,
                MintFailureCategory.SECOND_FACTOR_REQUIRED,
            )
        if not self._locator_optional(browser, self.config.control("alternate")):
            raise _failure(
                MintOutcome.SECOND_FACTOR_REQUIRED,
                MintFailureStage.CREDENTIAL,
                MintFailureCategory.SECOND_FACTOR_REQUIRED,
            )
        state.alternate_uses += 1
        state.alternate_transition_deadline = self._clock() + 10
        return GoogleLoopDirective.SETTLE

    def _handle_consent(
        self,
        browser: AuthBrowserSession,
        *,
        callback_complete: Callable[[], bool],
        observation: GoogleIdentityObservation,
        state: _GoogleDriveState,
    ) -> GoogleLoopDirective:
        if observation.unsupported_second_factor:
            if observation.alternate_visible:
                return self._handle_alternate(browser, state)
            if observation.totp_choice:
                return self._handle_totp_choice(browser, state)
            raise _failure(
                MintOutcome.SECOND_FACTOR_REQUIRED,
                MintFailureStage.CREDENTIAL,
                MintFailureCategory.SECOND_FACTOR_REQUIRED,
            )
        if state.consent_used:
            raise _failure(
                MintOutcome.UNKNOWN_FLOW,
                MintFailureStage.CALLBACK,
                MintFailureCategory.CONTROL_MISSING,
            )
        try:
            submitted = self._locator_optional(browser, self.config.control("consent"))
        except Exception:
            submitted = True
        if not submitted and (browser.page.is_closed() or callback_complete()):
            submitted = True
        if not submitted:
            raise _failure(
                MintOutcome.UNKNOWN_FLOW,
                MintFailureStage.CALLBACK,
                MintFailureCategory.CONTROL_MISSING,
            )
        state.consent_used = True
        return GoogleLoopDirective.SETTLE

    def _observe(
        self,
        browser: AuthBrowserSession,
        phase: AuthPhase,
    ) -> GoogleIdentityObservation:
        try:
            raw = observe_auth_ui(
                browser,
                self._observe_script,
                self.config.observations,
                phase=phase,
                publisher_hosts=(),
                auth_hosts=self._auth_hosts,
                identity_hosts=self.config.identity_hosts,
            )
            return GoogleIdentityObservation.model_validate(raw)
        except (AuthSelectorEvaluationError, ValidationError) as error:
            raise _failure(
                MintOutcome.UNKNOWN_FLOW,
                MintFailureStage.CREDENTIAL,
                MintFailureCategory.UNKNOWN,
            ) from error

    @staticmethod
    def _terminal(observation: GoogleIdentityObservation) -> None:
        if observation.account_alert:
            raise _failure(
                MintOutcome.ACCOUNT_ALERT,
                MintFailureStage.CREDENTIAL,
                MintFailureCategory.ACCOUNT_ALERT,
            )
        if observation.credential_rejected:
            raise _failure(
                MintOutcome.CREDENTIAL_REJECTED,
                MintFailureStage.CREDENTIAL,
                MintFailureCategory.CREDENTIAL_REJECTED,
            )
        if observation.unsupported_second_factor and not any(
            (
                observation.password_visible,
                observation.password_choice,
                observation.alternate_visible,
                observation.totp_choice,
                observation.totp_visible,
            )
        ):
            raise _failure(
                MintOutcome.SECOND_FACTOR_REQUIRED,
                MintFailureStage.CREDENTIAL,
                MintFailureCategory.SECOND_FACTOR_REQUIRED,
            )

    @staticmethod
    def _result(
        state: _GoogleDriveState,
        *,
        callback_complete: bool,
        identity_page_closed: bool,
        exit_reason: IdentityExitReason,
    ) -> GoogleIdentityResult:
        return GoogleIdentityResult(
            credential_action=state.action,
            callback_complete=callback_complete,
            identity_page_closed=identity_page_closed,
            exit_reason=exit_reason,
        )

    @staticmethod
    def _record_action(
        state: _GoogleDriveState,
        action: CredentialAction,
    ) -> None:
        if _ACTION_STRENGTH[action] > _ACTION_STRENGTH[state.action]:
            state.action = action

    @staticmethod
    def _page_closed(browser: AuthBrowserSession) -> bool:
        try:
            return bool(browser.page.is_closed())
        except Exception as error:
            return GoogleIdentityDriver._target_closed(error)

    @classmethod
    def _closed_handoff(
        cls,
        error: BaseException,
        browser: AuthBrowserSession,
        *,
        totp_submitted: bool = False,
    ) -> bool:
        if isinstance(error, AuthFailureBase) and (error.evidence.category != MintFailureCategory.INFRASTRUCTURE):
            return False
        return cls._target_closed(error) or (
            cls._context_replaced(error) and (totp_submitted or cls._page_closed(browser))
        )

    @staticmethod
    def _target_closed(error: BaseException) -> bool:
        chain: list[BaseException] = []
        current: BaseException | None = error
        while current is not None and current not in chain and len(chain) < 6:
            chain.append(current)
            name = type(current).__name__.casefold()
            message = str(current).casefold()
            if (
                "targetclosed" in name
                or ("target" in message and "closed" in message)
                or "page, context or browser has been closed" in message
            ):
                return True
            current = current.__cause__ or current.__context__
        return False

    def _prepare_browser(self, browser: AuthBrowserSession) -> None:
        browser.suppress_passkeys(PasskeyMode.NON_PRESENT)
        self._disable_webauthn_js(browser)

    @classmethod
    def _mouse_optional(
        cls,
        browser: AuthBrowserSession,
        selectors: tuple[str, ...],
    ) -> bool:
        try:
            target = browser.mouse_target(selectors)
            browser.mouse_click(target)
        except RuntimeError:
            return False
        return True

    @classmethod
    def _passkey_alternative_optional(
        cls,
        browser: AuthBrowserSession,
        selectors: tuple[str, ...],
    ) -> bool:
        with suppress(Exception):
            browser.press_page("Escape")
        browser.wait(0.35)
        try:
            browser.click(selectors)
            return True
        except Exception:
            return cls._mouse_optional(browser, selectors)

    def _click_cached_account(self, browser: AuthBrowserSession) -> bool:
        """Select the configured account tile using only the username reference.

        Both the credential flow and the cached-callback replay resolve the
        chooser this way, so the single-read boundary has one definition.
        """

        matcher = getattr(self._secrets, "click_matching_choice", None)
        if not callable(matcher):
            return False
        return bool(
            matcher(
                browser,
                secret_ref=self.config.secret_ref,
                field="username",
                selectors=self.config.control("account_choices"),
                excluded_text=("signed out",),
                allowed_origins=self.config.allowed_origins,
            )
        )

    @classmethod
    def _locator_optional(
        cls,
        browser: AuthBrowserSession,
        selectors: tuple[str, ...],
    ) -> bool:
        try:
            browser.click(selectors)
            return True
        except Exception:
            return cls._mouse_optional(browser, selectors)

    @classmethod
    def _totp_submit(
        cls,
        browser: AuthBrowserSession,
        selectors: tuple[str, ...],
    ) -> _SubmitAttempt:
        try:
            target = browser.mouse_target(selectors)
        except Exception as error:
            if cls._target_closed(error) or cls._context_replaced(error):
                return _SubmitAttempt.AMBIGUOUS_TRANSITION
            if isinstance(error, RuntimeError):
                return _SubmitAttempt.NOT_FOUND
            raise
        try:
            browser.mouse_click(target)
        except Exception:
            # Once geometry has been resolved, the click may have reached the
            # browser even if navigation destroys the caller's execution
            # context before it can observe the return.
            return _SubmitAttempt.AMBIGUOUS_TRANSITION
        return _SubmitAttempt.SUBMITTED

    @staticmethod
    def _context_replaced(error: BaseException) -> bool:
        chain: list[BaseException] = []
        current: BaseException | None = error
        while current is not None and current not in chain and len(chain) < 6:
            chain.append(current)
            current = current.__cause__ or current.__context__
        material = " ".join(f"{type(item).__name__} {item}".lower() for item in chain)
        return any(
            marker in material
            for marker in (
                "execution context",
                "context was destroyed",
                "frame was detached",
                "frame detached",
                "most likely because of a navigation",
            )
        )

    @staticmethod
    def _authenticator_text_optional(browser: AuthBrowserSession) -> bool:
        click_matching = getattr(browser, "click_matching_text", None)
        if not callable(click_matching):
            return False
        selectors = (
            "button",
            "a",
            "div[role='button']",
            "div[role='link']",
            "li",
            "li div",
            "[data-challengeid]",
            "[data-challengetype]",
            "div[jsname]",
            "div[data-action]",
            "div[tabindex]",
            "span[jsname]",
        )
        excluded = (
            "tap yes",
            "use your passkey",
            "fingerprint",
            "by text",
            "text message",
        )
        for phrase in (
            "google authenticator",
            "authenticator app",
            "authentication app",
            "phone or tablet to get a security code",
            "get a security code",
            "security code",
            "even if it's offline",
            "even if it is offline",
        ):
            try:
                if click_matching(selectors, phrase, excluded_text=excluded):
                    return True
            except TypeError:
                try:
                    if click_matching(selectors, phrase):
                        return True
                except Exception:  # noqa: S112 - never log page or credential details
                    continue
            except Exception:  # noqa: S112 - bounded fallback to another visible choice
                continue
        return False

    @staticmethod
    def _disable_webauthn_js(browser: AuthBrowserSession) -> None:
        with suppress(Exception):
            browser.add_init_script(
                """
                (() => {
                  try {
                    Object.defineProperty(window, 'PublicKeyCredential', {
                      configurable: true,
                      get: () => undefined,
                    });
                  } catch (_) {}
                  try {
                    if (navigator.credentials) {
                      navigator.credentials.get = () =>
                        Promise.reject(new DOMException('NotAllowedError'));
                      navigator.credentials.create = () =>
                        Promise.reject(new DOMException('NotAllowedError'));
                    }
                  } catch (_) {}
                })();
                """
            )


def _failure(
    outcome: MintOutcome,
    stage: MintFailureStage,
    category: MintFailureCategory,
) -> AcquisitionFailure:
    return AcquisitionFailure(
        outcome,
        MintFailureEvidence(stage=stage, category=category),
    )


__all__ = [
    "GoogleIdentityConfig",
    "GoogleIdentityDriver",
    "GoogleIdentityObservation",
    "GoogleIdentityResult",
    "GoogleIdentityStep",
    "google_identity_step",
]
