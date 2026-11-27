"""Render every shared connection-page component with invented data.

uv run python examples/connection_kit.py > kit.html
"""

import json

from signin_window.connections import (
    PageIdentity,
    SuiteDirectory,
    badge,
    disconnect_confirmation,
    page,
    timestamp,
)

APPS = [
    ("Ledger", "ledger", "Workspaces", "Balances and spending"),
    ("Shop", "shop", "Accounts", "Orders and basket"),
    ("Rides", "rides", "Accounts", "Trips and reservations"),
]


def render() -> str:
    directory = SuiteDirectory.from_json(
        json.dumps(
            {
                "name": "Example",
                "apps": [
                    {"label": label, "url": f"https://{host}.example.com/", "section": section, "description": text}
                    for label, host, section, text in APPS
                ],
            }
        )
    )
    suite = directory.suite(groups=[], current="https://shop.example.com/", account="Alex Example")
    form = "<form><button{}>{}</button></form>"
    body = (
        '<section class="panel hero"><div class="card-head"><h2>Your assistant’s basket</h2>'
        + badge("In use", "ok")
        + "</div><p><b>Sam Example’s Shop account</b></p>"
        '<p class="muted">Shared with you · read and change the basket</p><div class="actions">'
        + form.format("", "Use my own account")
        + form.format(' class="secondary"', "Leave shared account")
        + '</div></section><div class="grid-2"><article><div class="card-head"><h2>My account</h2>'
        + badge("Sign-in needed", "warn")
        + '</div><p class="muted">Connect your own account to give your assistant its own basket.</p>'
        '<div class="actions">'
        + form.format("", "Connect Shop")
        + "</div>"
        + timestamp("2026-01-02T08:04:00+00:00")
        + '</article><article><div class="card-head"><h2>Connection</h2>'
        + badge("Healthy", "ok")
        + '</div><dl class="facts"><dt>Account</dt><dd>sam@example.com</dd><dt>Access</dt><dd>Basket, orders</dd></dl>'
        + disconnect_confirmation(form.format(' class="danger"', "Disconnect"), "Shop", "Your assistant loses access.")
        + '</article></div><article><div class="card-head"><h2>People with access</h2>'
        + form.format(' class="secondary"', "Share access")
        + '</div><ul class="rows"><li><div class="who"><span class="avatar">S</span><span><b>Sam Example</b>'
        "<small>Can read and change the basket</small></span></div>"
        + badge("Active", "ok")
        + form.format(' class="quiet"', "Remove")
        + '</li><li><div class="who"><span class="avatar">R</span><span><b>Robin Example</b>'
        "<small>Can read order history</small></span></div>"
        + badge("Invited", "info")
        + form.format(' class="quiet"', "Remove")
        + '</li></ul></article><article><h2>How to connect</h2><ol class="steps">'
        "<li>Open the secure sign-in window.</li><li>Sign in as you normally would.</li>"
        '<li>Return here; the status updates on its own.</li></ol><div class="callout info">'
        "<p>Connecting does not give an assistant permission to use the account.</p></div></article>"
    )
    return page(
        "Shop",
        body,
        intro="Choose which basket your assistant uses.",
        identity=PageIdentity("example-shop", "1.2.3", "abcdef1234567890"),
        suite=suite,
    )


if __name__ == "__main__":
    print(render())
