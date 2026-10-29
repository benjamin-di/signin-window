"""Authentication mechanics must report observed actions and fail closed."""

from types import SimpleNamespace

import pytest

from signin_window.automation.auth import AuthObservationSpec, CredentialAction, SecretDeliveryError
from signin_window.automation.google import GoogleIdentityConfig, GoogleIdentityDriver, GoogleIdentityObservation
from signin_window.automation.secret_filler import OpSecretFiller
from signin_window.automation.secrets import OpSecretReader, SecretResolutionError


def config():
    controls = (
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
    )
    return GoogleIdentityConfig(
        provider_key="example",
        controls={key: (f"[data-control={key}]",) for key in controls},
        observations={
            key: AuthObservationSpec(any_selectors=(f"[data-state={key}]",))
            for key in GoogleIdentityObservation.model_fields
        },
        secret_ref="op://Example/Item",
        allowed_origins=frozenset({"https://accounts.google.com"}),
        identity_hosts=("accounts.google.com",),
    )


def test_existing_callback_needs_no_secret_or_page_observation():
    class Browser:
        page = SimpleNamespace(is_closed=lambda: False)

        def suppress_passkeys(self, mode):
            pass

        def add_init_script(self, script):
            pass

        def evaluate(self, script):
            pytest.fail("completed callback needs no credential inspection")

    secrets = SimpleNamespace(fill=lambda *a, **kw: pytest.fail("must reuse existing authority"))
    result = GoogleIdentityDriver(config(), secrets=secrets).drive(
        Browser(),
        callback_complete=lambda: True,
        resolve_challenge=lambda browser: None,
    )
    assert result.callback_complete
    assert result.credential_action is CredentialAction.NONE


def test_secret_origin_is_checked_again_after_resolution():
    browser = SimpleNamespace(current_url="https://accounts.google.com/start")
    browser.fill = lambda *a, **kw: pytest.fail("redirected origin must receive no secret")
    filler = OpSecretFiller(service_account_token="synthetic-authority")

    def read(*args, **kwargs):
        browser.current_url = "https://other.example.com/"
        return "synthetic-value"

    filler._read = read
    with pytest.raises(SecretDeliveryError, match="origin"):
        filler.fill(
            browser,
            secret_ref="op://Example/Item",
            field="password",
            selectors=("input",),
            allowed_origins=frozenset({"https://accounts.google.com"}),
        )


def test_secret_failure_never_switches_identity(monkeypatch):
    import subprocess

    calls = []

    def failed(args, **kwargs):
        calls.append(kwargs)
        raise subprocess.CalledProcessError(1, args)

    monkeypatch.setattr("signin_window.automation.secrets.subprocess.run", failed)
    with pytest.raises(SecretResolutionError):
        OpSecretReader(service_account_token="synthetic-authority").read("op://Example/Item/password")
    assert len(calls) == 1
    assert calls[0]["env"]["OP_SERVICE_ACCOUNT_TOKEN"] == "synthetic-authority"
    assert calls[0]["capture_output"] is True


def test_secret_read_keeps_only_the_configured_op_directory(monkeypatch):
    calls = []

    def resolved(args, **kwargs):
        calls.append(kwargs)
        return type("Completed", (), {"stdout": "synthetic-value\n"})()

    monkeypatch.setattr("signin_window.automation.secrets.subprocess.run", resolved)
    monkeypatch.setenv("OP_CONFIG_DIR", "/tmp/operator-cli")
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.example.com")
    reader = OpSecretReader(service_account_token="synthetic-authority")
    assert reader.read("op://Example/Item/password") == "synthetic-value"
    assert set(calls[0]["env"]) == {"OP_SERVICE_ACCOUNT_TOKEN", "PATH", "OP_CONFIG_DIR"}
    assert calls[0]["env"]["OP_CONFIG_DIR"] == "/tmp/operator-cli"

    monkeypatch.delenv("OP_CONFIG_DIR")
    reader.read("op://Example/Item/password")
    assert set(calls[1]["env"]) == {"OP_SERVICE_ACCOUNT_TOKEN", "PATH"}


def test_browser_child_never_inherits_operator_or_planner_credentials():
    from signin_window.automation.runtime import browser_environment

    environment = {
        "HOME": "/tmp/browser",
        "PATH": "/usr/bin",
        "TZ": "UTC",
        "OP_SERVICE_ACCOUNT_TOKEN": "synthetic-authority",
        "CLAUDE_CODE_OAUTH_TOKEN": "synthetic-planner-grant",
        "EXAMPLE_SSH_KEY": "synthetic-key",
        "HTTPS_PROXY": "http://proxy.example.com",
    }
    assert browser_environment(environment) == {"HOME": "/tmp/browser", "PATH": "/usr/bin", "TZ": "UTC"}


def test_explicit_empty_secret_identity_never_uses_ambient_authority(monkeypatch):
    monkeypatch.setenv("OP_SERVICE_ACCOUNT_TOKEN", "synthetic-authority")
    reader = OpSecretReader(service_account_token="")
    assert not reader.has_token
    with pytest.raises(SecretResolutionError, match="unavailable"):
        reader.read("op://Example/Item/password")
