"""Keeping a sign-in window on the site: which pages it may show and which hosts its browser may resolve.

A sign-in window shows a real browser to a person; it must not become a general browser. Two layers, both needed:

- ``allowed(url, hosts)``: a route check for every request the browser makes (Playwright's ``context.route``):
  only https (or the schemes you name), only these hosts and their subdomains. ``top_level(request)`` tells the
  pages a person sees (their address) from what those pages load, when the two get different hosts.
- ``host_resolver_rules(hosts)``: a Chromium flag making every other host resolve to nothing, so a redirect
  (which a route check sees only as its first URL) cannot reach anywhere else either. A proxy's own host stays
  resolvable (``proxy_hosts``).
"""

from __future__ import annotations

import os
from collections.abc import Iterable, Mapping
from typing import Any
from urllib.parse import urlsplit

PROXY_VARIABLES = ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy")


def host_matches(host: str, parent: str) -> bool:
    """Whether ``host`` is ``parent`` or one of its subdomains (case and a trailing dot ignored)."""
    host, parent = host.lower().rstrip("."), parent.lower().strip(".")
    return bool(parent) and (host == parent or host.endswith("." + parent))


def allowed(url: str, hosts: Iterable[str], schemes: Iterable[str] = ("https",)) -> bool:
    """Whether the window may request ``url``: one of ``schemes``, on one of ``hosts`` or their subdomains."""
    parts = urlsplit(url)
    if parts.scheme not in tuple(schemes) or parts.username or parts.password:
        return False
    host = parts.hostname or ""
    return any(host_matches(host, parent) for parent in hosts)


def top_level(request: Any) -> bool:
    """Whether a Playwright request loads a page's own document, the address the person sees, rather than a frame's
    or a resource. A popup's first page counts: Playwright has no frame for it yet and raises when asked."""
    if not request.is_navigation_request():
        return False
    try:
        frame = request.frame
    except Exception:  # Playwright's "Frame for this navigation request is not available": a popup's first page
        return True
    return frame.parent_frame is None


def proxy_hosts(env: Mapping[str, str] | None = None) -> list[str]:
    """The hosts of the proxies the environment names (they must still resolve)."""
    env = os.environ if env is None else env
    found: list[str] = []
    for name in PROXY_VARIABLES:
        value = env.get(name, "").strip()
        host = urlsplit(value if "://" in value else f"//{value}").hostname if value else None
        if host and host not in found:
            found.append(host)
    return found


def host_resolver_rules(hosts: Iterable[str], proxies: Iterable[str] = ()) -> str:
    """Chromium's ``--host-resolver-rules`` value: only ``hosts`` (and subdomains) and ``proxies`` resolve."""
    rules = ["MAP * ~NOTFOUND"]
    for host in hosts:
        host = host.strip(".").lower()
        if host:
            rules += [f"EXCLUDE {host}", f"EXCLUDE *.{host}"]
    rules += [f"EXCLUDE {host}" for host in proxies]
    return ", ".join(rules)
