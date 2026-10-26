# LinkedIn presentation adapter prototype

This optional Linux example hosts an expiring sign-in page around
`linkedin-mcp-server`'s manual login. It requires the prepared upstream hooks;
it does not add `signin-window` to that project's dependencies. The CLI requires
`--synthetic` and never offers a live-account launch.

The library owns the authenticated link, noVNC, loopback VNC and page lifecycle.
LinkedIn owns browser launch and proxy settings, Openbox, its profile claim and
lease, profile rotation, manual-login detection, portable cookie export, source
generation, restoration and browser shutdown. The adapter borrows the host's
dedicated X display and never closes it. A child process isolates configuration
and cancellation from the host's event loop. Session cookies stay in upstream's
normal files; only public progress crosses the child pipe.

The child calls `begin_saving()` from upstream's saving callback. The parent
acknowledges only after moving the window to saving, which refuses new viewers
and gates both directions of an existing stream. Closing the page then leaves
publication running. Success requires the upstream result, confirmed shutdown,
the source state and cookie file, a `connected` record, and exit 0. Cancellation
before saving gives upstream 45 seconds to restore its previous session.

## Run the acceptance

Use Python 3.13, `uv`, Git, Xvfb, x11vnc, Openbox, Chromium's Linux libraries, and
the checksum-verified noVNC 1.6.0 assets. From the library source:

```sh
NOVNC_DIR=/path/to/noVNC-1.6.0 bash publish/proposals/linkedin/verify.sh
```

The verifier fetches a pinned upstream commit into a temporary checkout, applies
the small hook patch, installs its locked environment, then runs unit checks and
the real-browser acceptance. Browser installation uses a private temporary cache
with garbage collection disabled. `LINKEDIN_TEST_CHROME` may name an already
installed browser; `SIGNIN_XVFB` and `SIGNIN_X11VNC` override the fixture binaries.
All created profiles are temporary and synthetic.

For manual inspection, use that environment with a dedicated existing display:

```sh
python examples/linkedin/app.py --synthetic --display :99 \
  --profile /tmp/synthetic-linkedin/auth/profile \
  --token-file /path/to/private-token-file --novnc-dir /path/to/noVNC-1.6.0
```

The token file must contain at least 32 random characters. `POST /link` on
`http://127.0.0.1:8766` requires `Authorization: Bearer <token>` and returns the
expiring page address. Only one configured account/profile can be selected;
requests cannot supply a profile path. Open the page, choose Connect, and use
the synthetic sign-in button through the viewer. Existing MCP tools are untouched.

## Scope of the evidence

Four acceptance cases drive actual Chromium through noVNC: reload and successful
publication with lease contention, closing the page while saving, cancellation
with restoration of an existing generation, and export failure without success.
The synthetic provider fulfills the sign-in/feed documents and aborts every other
context request. Native browser launch and upstream session mechanics stay real.

This proves the adapter boundary on Linux amd64, not live LinkedIn authentication,
fingerprint equivalence across platforms, production proxy routing, or mobile
usability. No browser identity or launch configuration changes are proposed.
The viewer controls the whole X display, so the host must dedicate it to login.
The existing upstream Docker viewer remains useful without this adapter; hosted
applications benefit from expiring links, reconnection and shared lifecycle code.
Upstream issues #1385/#1403 cover paste and browser confinement separately.

The prepared review bundle at `publish/proposals/linkedin/` is kept only in the
source repository and is excluded from the public library export.
