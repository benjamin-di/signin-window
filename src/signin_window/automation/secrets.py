"""Browser-free resolution of complete ``op://`` secret references."""

from __future__ import annotations

import math
import os
import subprocess


class SecretResolutionError(RuntimeError):
    """A configured field could not be resolved."""


class OpSecretReader:
    """Resolve complete ``op://`` references with the explicitly supplied identity.

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
        self._token = (
            service_account_token if service_account_token is not None else os.environ.get("OP_SERVICE_ACCOUNT_TOKEN")
        )
        self._read_timeout_seconds = float(read_timeout_seconds)

    @property
    def has_token(self) -> bool:
        return bool(self._token)

    def read(self, reference: str) -> str:
        """Resolve one complete reference, including its field segment."""

        ambient_token = self._token
        if not ambient_token:
            raise SecretResolutionError("1Password service token is unavailable")
        if not reference.startswith("op://") or any(marker in reference for marker in ("\r", "\n", "{{", "}}")):
            raise SecretResolutionError("1Password secret reference is invalid")
        try:
            return self._inject(reference, token=ambient_token)
        except (OSError, subprocess.SubprocessError) as error:
            raise SecretResolutionError("1Password field resolution failed") from error

    def _inject(self, reference: str, *, token: str) -> str:
        environment = {
            "OP_SERVICE_ACCOUNT_TOKEN": token,
            "PATH": os.environ.get("PATH", os.defpath),
        }
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


__all__ = ["OpSecretReader", "SecretResolutionError"]
