"""Synthetic third-party backend acceptance; no credential environment required."""

import sys
from types import ModuleType

import pytest

from signin_window.automation.auth import SecretDeliveryError
from signin_window.automation.secret_filler import CredentialFiller, configured_credential_filler
from signin_window.automation.secrets import load_credential_reader


class Reader:
    available = True
    calls = 0

    def read_field(self, reference, *, field):
        self.calls += 1
        assert reference == "example:account"
        return "123456" if field == "totp" else "SYNTHETIC_VALUE"


class Browser:
    current_url = "https://example.com/login"
    fills = None

    def fill(self, selectors, value, **kwargs):
        self.fills = (selectors, value)


def test_configured_third_party_backend_needs_no_op_token(monkeypatch):
    monkeypatch.delenv("OP_SERVICE_ACCOUNT_TOKEN", raising=False)
    module = ModuleType("synthetic_credentials")
    module.create = Reader
    monkeypatch.setitem(sys.modules, module.__name__, module)
    filler = configured_credential_filler("synthetic_credentials:create")
    browser = Browser()
    filler.fill(
        browser,
        secret_ref="example:account",
        field="password",
        selectors=("input",),
        allowed_origins=frozenset({"https://example.com"}),
    )
    assert browser.fills == (("input",), "SYNTHETIC_VALUE")


def test_foreign_origin_never_reads_backend_and_navigation_race_never_fills():
    reader = Reader()
    filler = CredentialFiller(reader=reader)
    browser = Browser()
    browser.current_url = "https://foreign.example/login"
    with pytest.raises(SecretDeliveryError):
        filler.fill(
            browser,
            secret_ref="example:account",
            field="password",
            selectors=("input",),
            allowed_origins=frozenset({"https://example.com"}),
        )
    assert reader.calls == 0
    browser.current_url = "https://example.com/login"

    def read(*args, **kwargs):
        browser.current_url = "https://foreign.example/login"
        return "SYNTHETIC_VALUE"

    reader.read_field = read
    with pytest.raises(SecretDeliveryError):
        filler.fill(
            browser,
            secret_ref="example:account",
            field="password",
            selectors=("input",),
            allowed_origins=frozenset({"https://example.com"}),
        )
    assert browser.fills is None


def test_backend_error_is_redacted_and_never_falls_back(monkeypatch):
    monkeypatch.setenv("OP_SERVICE_ACCOUNT_TOKEN", "SYNTHETIC_TOKEN")
    with pytest.raises(Exception, match="unavailable") as result:
        load_credential_reader("absent_backend:create")
    assert "SYNTHETIC" not in str(result.value)
    reader = Reader()

    def fail(*args, **kwargs):
        raise ValueError("SYNTHETIC_SECRET_LEAK")

    reader.read_field = fail
    with pytest.raises(SecretDeliveryError) as result:
        CredentialFiller(reader=reader).fill(
            Browser(),
            secret_ref="example:account",
            field="password",
            selectors=("input",),
            allowed_origins=frozenset({"https://example.com"}),
        )
    assert "SYNTHETIC_SECRET_LEAK" not in str(result.value)
