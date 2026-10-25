import os

import pytest

from signin_window.browser import browser_environment
from signin_window.state import PrivateStateError, read_private_file


def test_private_file_reader_preserves_missing_and_bounds_payload(tmp_path):
    path = tmp_path / "state"
    with pytest.raises(FileNotFoundError):
        read_private_file(path, max_bytes=8)
    path.write_bytes(b"12345678")
    assert read_private_file(path, max_bytes=8) == b"12345678"
    with pytest.raises(PrivateStateError):
        read_private_file(path, max_bytes=7)


def test_private_file_reader_rejects_redirects_and_nonregular_state(tmp_path):
    target = tmp_path / "target"
    target.write_bytes(b"synthetic")
    link = tmp_path / "link"
    link.symlink_to(target)
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    for path in (link, fifo, tmp_path):
        with pytest.raises(PrivateStateError):
            read_private_file(path, max_bytes=64)


def test_human_browser_environment_excludes_operator_authority():
    supplied = {
        "DISPLAY": ":91",
        "HOME": "/tmp/browser",
        "PATH": "/usr/bin",
        "OP_SERVICE_ACCOUNT_TOKEN": "synthetic-operator",
        "LOGIN_SERVICE_TOKEN": "synthetic-login",
        "SSH_AUTH_SOCK": "/tmp/agent",
        "HTTP_PROXY": "https://proxy.example.com",
        "MODEL_API_KEY": "synthetic-model",
    }
    assert browser_environment(supplied) == {"DISPLAY": ":91", "HOME": "/tmp/browser", "PATH": "/usr/bin"}
