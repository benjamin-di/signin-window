"""Static boundaries of the package. The person does every step of a sign-in: nothing here automates a page. Only the
client talks to the network, and only to the login service. The paste add-on keeps nothing."""

from __future__ import annotations

import ast
import re
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src" / "signin_window"
PYTHON = sorted(SRC.rglob("*.py"))
# Modules that open connections (urllib.parse, say, only parses).
NETWORK = ("urllib.request", "http.client", "httpx", "requests", "aiohttp", "socket", "websockets")


def imports(path: Path) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text())):
        if isinstance(node, ast.Import):
            names |= {alias.name for alias in node.names}
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            names.add(node.module)
    return names


def network(names: set[str]) -> set[str]:
    return {name for name in names if any(name == m or name.startswith(m + ".") for m in NETWORK)}


def test_nothing_clicks_types_or_fills_a_page():
    automation = re.compile(
        r"\.(click|dblclick|fill|type|press|check|select_option|set_input_files|tap)\(|keyboard\.|mouse\."
    )
    for path in PYTHON:
        assert not automation.search(path.read_text()), path.name


def test_only_the_client_reaches_the_network():
    for path in PYTHON:
        found = network(imports(path))
        if path.name == "client.py":
            assert found <= {"urllib.request", "websockets.asyncio.client", "websockets.exceptions"}, found
        elif path.name == "service.py":  # its own VNC servers' ports on loopback
            assert found <= {"socket"}, found
            hosts = re.findall(r"\.(?:bind|connect_ex|open_connection)\(\(?([^,)]*)", path.read_text())
            assert hosts and set(hosts) == {'"127.0.0.1"'}, hosts
        else:
            assert not found, (path.name, found)


def test_the_paste_add_on_types_without_logging_or_keeping_the_text():
    source = (SRC / "static" / "paste.js").read_text()
    assert 'import UI from "./app/ui.js"' in source  # the same UI singleton vnc.html loads
    for leak in ("console.", "localStorage", "sessionStorage", "fetch(", "XMLHttpRequest", "sendBeacon", "indexedDB"):
        assert leak not in source, leak
    keydown = source[source.index('addEventListener("keydown"') : source.index('addEventListener("paste"')]
    assert "stopPropagation()" in keydown and "preventDefault()" not in keydown  # the browser must still paste


def test_the_vnc_server_listens_on_loopback_only_without_a_password_prompt():
    service = (SRC / "service.py").read_text()
    assert '"-localhost"' in service and '"-nolisten", "tcp"' in service
