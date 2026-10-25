"""Origin-scoped, just-in-time secret delivery for browser acquisition."""

from __future__ import annotations

import re
from contextlib import nullcontext
from urllib.parse import urlsplit

from .auth import AuthBrowserSession as BrowserSession
from .auth import SecretDeliveryError as LoginInfrastructureError
from .secrets import (
    CredentialReader,
    OpCredentialReader,
    SecretField,
    SecretResolutionError,
    load_credential_reader,
    validate_credential_reference,
)

_SECRET_FIELDS = frozenset({"username", "password", "totp"})


class CredentialFiller:
    """Resolve one field just in time and pass it directly to the browser."""

    def __init__(
        self,
        *,
        reader: CredentialReader,
        step=None,
    ) -> None:
        self._step = step or (lambda name: nullcontext())
        self._reader = reader

    def fill(
        self,
        browser: BrowserSession,
        *,
        secret_ref: str,
        field: SecretField,
        selectors: tuple[str, ...],
        allowed_origins: frozenset[str],
        all_visible: bool = False,
    ) -> None:
        if _origin(browser.current_url) not in allowed_origins:
            raise LoginInfrastructureError("secret fill origin is not allowed")
        if not self._reader.available:
            raise LoginInfrastructureError("credential reader is unavailable")
        with self._step("secret_resolve"):
            value = self._read(secret_ref=secret_ref, field=field)
        try:
            with self._step("credential_apply"):
                if _origin(browser.current_url) not in allowed_origins:
                    raise LoginInfrastructureError("secret fill origin is not allowed")
                fill_all = getattr(browser, "fill_all_visible", None)
                if all_visible and callable(fill_all):
                    fill_all(
                        selectors,
                        value,
                        allowed_origins=allowed_origins,
                    )
                else:
                    browser.fill(
                        selectors,
                        value,
                        allowed_origins=allowed_origins,
                    )
        finally:
            del value

    def click_matching_choice(
        self,
        browser: BrowserSession,
        *,
        secret_ref: str,
        field: SecretField,
        selectors: tuple[str, ...],
        excluded_text: tuple[str, ...],
        allowed_origins: frozenset[str],
    ) -> bool:
        if _origin(browser.current_url) not in allowed_origins:
            raise LoginInfrastructureError("secret match origin is not allowed")
        click_matching = getattr(browser, "click_matching_text", None)
        if not callable(click_matching):
            return False
        wait_for_visible = getattr(browser, "wait_for_visible", None)
        if callable(wait_for_visible) and not wait_for_visible(
            selectors,
            timeout_seconds=10,
        ):
            return False
        with self._step("secret_resolve"):
            value = self._read(secret_ref=secret_ref, field=field)
        try:
            with self._step("credential_apply"):
                if _origin(browser.current_url) not in allowed_origins:
                    raise LoginInfrastructureError("secret match origin is not allowed")
                return bool(
                    click_matching(
                        selectors,
                        value,
                        excluded_text=excluded_text,
                        allowed_origins=allowed_origins,
                    )
                )
        finally:
            del value

    def _read(self, *, secret_ref: str, field: SecretField) -> str:
        try:
            validate_credential_reference(secret_ref)
            if field not in _SECRET_FIELDS:
                raise SecretResolutionError("credential reference field is invalid")
            value = self._reader.read_field(secret_ref, field=field)
        except Exception:
            # Backends may raise errors containing the reference or secret.
            raise LoginInfrastructureError("credential reference resolution failed") from None
        return self._validate_field(value, field=field)

    @staticmethod
    def _validate_field(value: str, *, field: SecretField) -> str:
        if not isinstance(value, str) or not value:
            raise LoginInfrastructureError("credential field is empty")
        if field == "totp" and re.fullmatch(r"[0-9]{6,8}", value) is None:
            raise LoginInfrastructureError("credential reader did not return a generated one-time code")
        return value


def _origin(url: str) -> str:
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError:
        return ""
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        return ""
    host = parsed.hostname.lower()
    default_port = (parsed.scheme == "https" and port == 443) or (parsed.scheme == "http" and port == 80)
    port_suffix = "" if port is None or default_port else f":{port}"
    return f"{parsed.scheme}://{host}{port_suffix}"


class OpSecretFiller(CredentialFiller):
    """Compatibility adapter using the existing 1Password identity and syntax."""

    def __init__(self, *, service_account_token: str | None = None, read_timeout_seconds: float = 30, step=None):
        super().__init__(
            reader=OpCredentialReader(
                service_account_token=service_account_token, read_timeout_seconds=read_timeout_seconds
            ),
            step=step,
        )


def configured_credential_filler(factory: str = "", *, step=None) -> CredentialFiller:
    """Use an explicit backend, or the existing 1Password adapter by default."""
    if factory:
        return CredentialFiller(reader=load_credential_reader(factory), step=step)
    return OpSecretFiller(step=step)
