# Amazon remote human sign-in prototype

This example composes upstream `amazon-orders-mcp` tools with an expiring human
sign-in link. It uses `PlaywrightBrowserLogin` for browser selection and login,
`AmazonSession.import_cookies` for independent verification and atomic publication,
and `SavedSession.sign_in_with` for the site's tool lock. signin-window supplies
the display/viewer and lifetime. The application retains its session; no cookie
payload crosses an HTTP result endpoint.

The default provider is entirely synthetic and listens on loopback. The browser
route allowlist refuses external origins in synthetic mode. No account, password,
OTP or real provider page is used. The only action is a local form button.

## Source requirements

This prototype needs three proposed upstream extension points, not yet released:

1. `PlaywrightBrowserLogin.launch_env()` and launcher environment forwarding.
2. `AmazonSession.import_cookies()` with isolated verification before saving.
3. `SavedSession.sign_in_with(callback, site)` for application-owned sign-in.

Install the prepared source trees together in a separate environment, from a
directory containing `amazon-orders/`, `amazon-orders-mcp/` and `signin-window/`:

```sh
uv venv prototype-venv
uv pip install --python prototype-venv/bin/python ./amazon-orders ./amazon-orders-mcp ./signin-window \
  playwright uvicorn pytest httpx
prototype-venv/bin/python -m playwright install chromium
```

The accompanying review bundle contains replayable upstream patches, base commit
IDs, issue packets and a verification script. The example
never imports private upstream internals. The upstream packages acquire no
signin-window dependency, and local sign-in/tool schemas remain unchanged.

## Run locally

Use Linux with Xvfb, x11vnc, and the pinned noVNC 1.6.0 assets described in the
library's minimal Dockerfile. Create a private random token file, then run:

```sh
prototype-venv/bin/python signin-window/examples/amazon/app.py \
  --state /tmp/amazon-prototype-state --token-file /path/to/private-token \
  --novnc-dir /opt/novnc
```

Connect an MCP client to `http://127.0.0.1:8765/mcp` using that bearer, call
`amazon_connect`, open the returned link and click the synthetic sign-in button.
After completion, `check_session` uses the published session. MCP calls require
the bearer; the viewer requires its own expiring link.

`--amazon` selects the actual provider and requires the managed Chromium policy.
Use that option only on an authorized deployed host. Actual Amazon login has not
been qualified by this prototype. Stored/configured credentials and `AMAZON_`
environment overrides are refused. The application binds loopback by default.

## Acceptance

With the three patched packages installed and browser/display dependencies ready:

```sh
SIGNIN_XVFB=Xvfb SIGNIN_X11VNC=x11vnc NOVNC_DIR=/opt/novnc \
  prototype-venv/bin/python -m pytest signin-window/examples/amazon/test_acceptance.py -v
```

These tests drive real Chromium through noVNC, including remote keyboard input,
and use the real upstream tools over MCP. They cover reload without another
login, failure preserving the previous jar, saving after page closure, explicit
cancel/cleanup, and refusing publication by a superseded attempt. Library tests
also cover expiry without any requests and shutdown while saving. Upstream
tests cover failed publication, changed jars and foreign-cookie rejection.

## Limits

This is one application process with one publisher per session root. The normal
Amazon cookie-file lock coordinates threads, not arbitrary CLI/other-process
writers. The import's revision check detects replacement during verification but
is not a cross-process compare-and-swap. Adding a shared writer lease requires
agreement across every writer. Session continuity across a process restart,
mobile/password-manager acceptance and remote acknowledged handover are not
claimed here. The existing tool's `sign_in` remains a local-browser operation;
the added instructions direct remote users to `amazon_connect`.
