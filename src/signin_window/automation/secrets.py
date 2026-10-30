"""Browser-free resolution of complete ``op://`` secret references."""

from __future__ import annotations

import importlib
import math
import os
import subprocess
from typing import Literal, Protocol

SecretField = Literal["username", "password", "totp"]


class CredentialReader(Protocol):
    """Explicit, trusted backend; availability checks must not resolve secrets."""

    @property
    def available(self) -> bool: ...

    def read_field(self, reference: str, *, field: SecretField) -> str: ...


def validate_credential_reference(reference: str) -> str:
    """Validate an opaque reference without interpreting a backend's syntax."""
    if (
        not isinstance(reference, str)
        or not reference.strip()
        or len(reference) > 2048
        or any(c in reference for c in ("\r", "\n", "\x00", "{", "}"))
    ):
        raise SecretResolutionError("credential reference is invalid")
    return reference


def load_credential_reader(factory: str) -> CredentialReader:
    """Load only an explicitly configured module:factory; never fall back."""
    module, separator, name = factory.partition(":")
    if not separator or not module or not name.isidentifier():
        raise SecretResolutionError("credential reader must be module:factory")
    try:
        reader = getattr(importlib.import_module(module), name)()
        if not callable(getattr(reader, "read_field", None)) or type(reader.available) is not bool:
            raise ValueError("invalid reader")
        return reader
    except Exception:
        raise SecretResolutionError("configured credential reader is unavailable") from None


class SecretResolutionError(RuntimeError):
    """A configured field could not be resolved."""


class OpSecretReader:
    """Resolve complete ``op://`` references with one identity: explicit, Connect or service account.

    A failed read never escalates to another vault or service-account identity.
    """

    def __init__(
        self,
        *,
        service_account_token: str | None = None,
        read_timeout_seconds: float = 30,
    ) -> None:
        if not math.isfinite(read_timeout_seconds) or read_timeout_seconds <= 0:
            raise ValueError("secret read timeout must be positive")
        # An explicit token, even an empty one, is the only identity. Otherwise the ambient one: a 1Password
        # Connect server (OP_CONNECT_HOST and OP_CONNECT_TOKEN, which op prefers) or a service account.
        self._identity: dict[str, str] = {}
        if service_account_token is not None:
            if service_account_token:
                self._identity = {"OP_SERVICE_ACCOUNT_TOKEN": service_account_token}
        elif os.environ.get("OP_CONNECT_HOST") and os.environ.get("OP_CONNECT_TOKEN"):
            self._identity = {
                "OP_CONNECT_HOST": os.environ["OP_CONNECT_HOST"],
                "OP_CONNECT_TOKEN": os.environ["OP_CONNECT_TOKEN"],
            }
        elif token := os.environ.get("OP_SERVICE_ACCOUNT_TOKEN"):
            self._identity = {"OP_SERVICE_ACCOUNT_TOKEN": token}
        self._read_timeout_seconds = float(read_timeout_seconds)

    @property
    def has_token(self) -> bool:
        return bool(self._identity)

    def read(self, reference: str) -> str:
        """Resolve one complete reference, including its field segment."""

        if not self._identity:
            raise SecretResolutionError("1Password service token is unavailable")
        if not reference.startswith("op://") or any(marker in reference for marker in ("\r", "\n", "{{", "}}")):
            raise SecretResolutionError("1Password secret reference is invalid")
        try:
            return self._inject(reference)
        except (OSError, subprocess.SubprocessError) as error:
            raise SecretResolutionError("1Password field resolution failed") from error

    def _inject(self, reference: str) -> str:
        environment = {**self._identity, "PATH": os.environ.get("PATH", os.defpath)}
        # op writes its configuration on every call; a hardened container points it at a writable directory.
        if config_dir := os.environ.get("OP_CONFIG_DIR"):
            environment["OP_CONFIG_DIR"] = config_dir
        completed = subprocess.run(
            ["op", "inject"],
            check=True,
            capture_output=True,
            text=True,
            shell=False,
            env=environment,
            input=f"{{{{ {reference} }}}}\n",
            timeout=self._read_timeout_seconds,
        )
        value = completed.stdout.rstrip("\r\n")
        if not value:
            raise SecretResolutionError("1Password field was empty")
        return value


class OpCredentialReader:
    """1Password adapter for the backend-independent field reader contract."""

    def __init__(self, *, service_account_token: str | None = None, read_timeout_seconds: float = 30):
        self._reader = OpSecretReader(
            service_account_token=service_account_token, read_timeout_seconds=read_timeout_seconds
        )

    @property
    def available(self) -> bool:
        return self._reader.has_token

    def read_field(self, reference: str, *, field: SecretField) -> str:
        validate_credential_reference(reference)
        if not reference.startswith("op://") or field not in {"username", "password", "totp"}:
            raise SecretResolutionError("1Password secret reference is invalid")
        suffix = "one-time password?attribute=otp" if field == "totp" else field
        return self._reader.read(f"{reference.rstrip('/')}/{suffix}")


__all__ = [
    "CredentialReader",
    "OpCredentialReader",
    "OpSecretReader",
    "SecretField",
    "SecretResolutionError",
    "load_credential_reader",
    "validate_credential_reference",
]
