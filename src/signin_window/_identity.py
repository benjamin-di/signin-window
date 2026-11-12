"""Build identity for application-owned sign-in shells."""

from __future__ import annotations

import html
from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from .connections import PageIdentity

_STYLE = """
#page-identity{position:static;flex-shrink:0;padding:.45rem 1rem;border-top:1px solid #ddd;
font:12px/1.4 system-ui,sans-serif;color:#555;background:#fff;overflow-wrap:anywhere;user-select:text}
#page-identity small{font-size:inherit}
#page-identity summary{cursor:pointer;min-height:24px;list-style-position:inside}
#page-identity p{margin:.25rem 0 0}
#page-identity code{display:block;white-space:normal;overflow-wrap:anywhere;user-select:all}
#page-identity summary:focus-visible{outline:3px solid #a35d00;outline-offset:3px}
"""


def footer(identity: PageIdentity, *, element_id: Literal["page-identity", "connection-identity"]) -> str:
    service = html.escape(identity.service.strip() or "unknown", quote=True)
    version = html.escape(identity.version.strip() or "dev", quote=True)
    revision = identity.source_revision.strip() or "unknown"
    escaped_revision = html.escape(revision, quote=True)
    return (
        f'<footer id="{element_id}" data-service="{service}" data-version="{version}" '
        f'data-source-revision="{escaped_revision}" title="Source revision: {escaped_revision}">'
        f"<details><summary><small>{service} v{version} · {html.escape(revision[:12])}</small></summary>"
        f"<p>Source revision</p><code>{escaped_revision}</code></details></footer>"
    )


def stamp(markup: str, identity: PageIdentity | None, *, style: str = "", inline_style: bool = True) -> str:
    """Leave legacy output intact; stamp only the host-provided, escaped identity."""
    if identity is None:
        return markup
    identity_footer = footer(identity, element_id="page-identity")
    if inline_style:
        if "</style>" in markup:
            markup = markup.replace("</style>", _STYLE + style + "</style>", 1)
        else:
            markup = f"<style>{_STYLE}{style}</style>" + markup
    if "</html>" in markup:
        before, closing, after = markup.rpartition("</html>")
        return before + identity_footer + "\n" + closing + after
    return markup + identity_footer
