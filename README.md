# signin-window

Human sign-in windows, reusable session-maintenance primitives and optional
bounded browser-challenge mechanics for self-hosted applications.

Let a person sign in to a website **themselves**, from their own browser or phone, in a browser window that runs on
your server. Your server keeps the session afterwards; the password, the one-time code and the site's checks stay
with the person.

It is made for [MCP](https://modelcontextprotocol.io) servers and other headless services that act on a site for
someone (shops, rides, photos, mail) but should never hold their password or automate a sign-in. Your assistant
calls a tool, gets a one-time link, and gives it to the person. They open the site's own sign-in page through that
link, and the page notices when they are in.

```
person's browser ──https──> your server (relay) ──private network──> login service
  the link's page              /connect/<id>                          Xvfb + x11vnc + Chromium
  noVNC viewer  <──────────── live view (WebSocket) ────────────────  on the site's sign-in page
```

- **The login service** (`signin_window.service`) runs sign-in windows: a virtual display, a remote-desktop server
  on loopback, and your *runner*, which opens the site's sign-in page on that display (with Playwright, say) and
  waits until the site has signed the person in. It stays on a private network, behind a bearer.
- **The relay** (`signin_window.relay`) runs in your server: one-time links, their page, noVNC's files and the live
  view, carried through to the login service. When the window ends, your hook stores the session.
- **The paste add-on** lets the person paste into the remote page with Ctrl+V (Cmd+V), which noVNC alone does not.

The human window and relay APIs never click, type or fill a page: the person
does every step of the sign-in. They never import optional automation modules.

Applications can also use the session-maintenance primitives and explicitly
configured challenge mechanics described below. These are separate capabilities:
enabling a human sign-in link never enables automated interaction.

## Embedded human viewing

An application can keep its browser, verification and session publication together
and use the viewer without a separate HTTP login service:

```python
from signin_window.client import LocalBackend
from signin_window.page import PageText
from signin_window.relay import Relay
from signin_window.service import Windows

# Inside the host's async lifespan, on its event loop:
windows = Windows(application_login_runner, save_seconds=45)
relay = Relay(
    LocalBackend(windows, "/opt/novnc"),
    "https://mcp.example.com/connect",
    text=PageText(service="Example", reconnect=True),
)
# Mount relay.routes("/connect"), then hold both contexts for the host lifetime:
# async with windows.lifespan(), relay.lifespan():
#     yield
```

The application runner calls `waiting(host)` when its login page is ready,
`saving()` before verification/publication, then `finish("connected")` only after
the application accepts the session. No session payload needs to cross the viewer
boundary. `LocalBackend`'s synchronous methods run on worker threads; the relay
dispatches them there. Browser children should receive the window's display in
their own environment; never change the host process's `DISPLAY` for a login.

`Windows(display=":99")` borrows an existing local display (one slot). It owns its
VNC child, not that display, window manager, browser or persistent profile. The
normal mode still creates an isolated Xvfb display per window.

The window lifespan enforces expiry without requests and drains accepted saves
on shutdown, within `save_seconds`. Synchronous runners must honor cancellation
and bound their I/O; a Python thread cannot be forcibly stopped. The relay
lifespan reconciles completion without page polling; `relay.app()` installs it
automatically. When mounting routes, install it explicitly in the parent lifespan.

`PageText(reconnect=True)` reattaches a reloaded page and provides explicit Cancel.
Closing the page keeps the attempt until Cancel or its original deadline; it does
not add an unbounded session or renew the deadline. The default retains the older
page-close cancellation behavior. Accepted saving closes browser control and
continues independently of the viewer. Applications own stale-attempt checks and
publication locks.

[`examples/amazon`](examples/amazon/README.md) demonstrates this boundary against
a local synthetic provider and upstream Amazon tools. It requires the proposed
upstream hooks described there; it is not a production deployment configuration.
The existing HTTP handover protocol is unchanged: acknowledged remote transfer is
separate work, and is not needed for the embedded kept-session integration.

See the [roadmap](ROADMAP.md) for planned reliability, reconnect and maintenance
improvements, including the scope of 1Password and passkey support.

## Authenticated sign-in attempts

The [permissions model](PERMISSIONS.md) separates browser identity, attempt
ownership, provider-account management and an agent's API access. Applications
own those policies; using a sign-in window grants no agent permission.

Hosts with an existing browser session can protect sign-in links without adding
an identity-provider dependency to this package. Supply `Relay(authorize=...)`
and pass a private `AttemptContext(owner=..., requester=..., target=...)` to
`create()`. The host assigns opaque references from verified identity, account
bindings and application revisions, never from untrusted request fields. They
are absent from public state, backend start parameters and the link's repr.

`authorize(connection, link, operation)` returns exactly `True` to permit access;
it may be async. Operations are `page`, `start`, `state`, `cancel`, `novnc` and
`vnc`. The hook runs on every protected route, before forwarding either direction
of a viewer stream, and periodically while a stream is idle. Denials close the
stream and reveal no account label. Hook errors deny access and log only their
exception type; async decisions have a five-second bound. Synchronous hooks must
not block. The host owns login redirects, session expiry and current permissions.
Authenticated POSTs and WebSockets require an exact same-origin `Origin` header
matching the configured public URL; configure proxies to preserve it.

The default capability-link mode remains available for existing applications.
Once an authorization hook is configured, missing context or failed authentication
never falls back to capability access. Missing owner context is refused at link
creation. A GET preview never starts a browser.

Use `PageText(reconnect=True, return_url="/connections/")` for reload recovery,
explicit cancellation and local return navigation. Saving removes the live view
and may complete after the page closes. A sign-in attempt is not a durable account
connection: the host checks provider identity, entitlement and revision before
publication and reads lasting connection health from its own backend. On restart,
in-memory attempts are unavailable; the host reconciles saved application state
and does not claim an unknown browser can be resumed. Remote result transfer keeps
its existing contract and is not made transactional by authentication.

The [existing-session example](examples/authenticated.py) illustrates the public
boundary. The Google Photos application supplies a standard OIDC connection
screen using the same hooks; issuer configuration, permissions and session data
belong to that host. Ordinary applications can keep their own authentication.

## Session maintenance

`signin_window.sessions` supplies durable attempt accounting, warm-first upkeep
and refresh scheduling without choosing a site's session format or policy.
It starts no worker and reads no credentials. Applications own account checks,
holds, schedules, session verification and publication.

```python
from pathlib import Path
from signin_window.sessions import AttemptBudget, WarmFirst

budget = AttemptBudget(Path("/private/state/example-account/attempts"))


def sign_in_once():
    if not budget.reserve("example", limit=1):
        raise RuntimeError("sign-in budget exhausted")
    # Call the application's explicitly authorized sign-in adapter here.


# Supply application callbacks and its positive signed-out exception:
# flow = WarmFirst(refresh_and_verify, sign_in_once, signed_out=SignedOut)
# published_generation = flow.run()
```

`WarmFirst` calls `refresh` first. Only the supplied signed-out exception permits
one sign-in and one subsequent refresh; transient failures, challenges and
inconclusive evidence propagate without signing in. `SessionStillDead` means
the new session remained signed out; the application should retain an operator
hold. `refresh_due` coordinates regular checks, failure spacing and bounded
early-refresh requests. No helper treats a successful sign-in as entitlement
to application content.

`AttemptBudget` records a reservation before dispatch under a process-safe
lock. It retains interrupted and failed attempts. The default rolling window
is 24 hours; files use `{"attempts": ["2030-01-01T00:00:00+00:00"]}`. Malformed
or symlinked state fails closed. Keep each tenant/account's root separate and
preserve its ledger during upgrades. `signin_window.state` provides atomic
private writes and bounded regular-file reads; `signin_window.leases` provides ordered session, attempt and
profile leases. All processes sharing a profile must use the same lease path.

## Optional challenge automation

Install `signin-window[automation]` for typed visual plans and bounded hCaptcha
and reCAPTCHA image-grid mechanics. Importing these modules starts no browser
or model request. The caller supplies the browser, a `VisionPlanner`, explicit
authorization and site-specific acceptance checks. There is no built-in model
account, credential store or implicit planner fallback.

- `signin_window.automation.hcaptcha.HCaptchaVisualMechanic` accepts an explicit
  planner and acceptance probe; only independently observed acceptance succeeds.
- `signin_window.automation.recaptcha.RecaptchaImageSelectSolver` handles a
  visible image grid; its result only says the challenge cleared.
- `signin_window.automation.plans` validates bounded grid, point and drag plans.
  A slow planner cannot apply an action to a replaced challenge task.
- `signin_window.automation.detection.detect_challenge` passively classifies
  challenge surfaces. `automation.resolver.ChallengeResolver` dispatches only
  the caller's configured mechanics, with explicit mode and deadline. A cleared
  challenge still needs the application's independent access check.

Keep human and automated runners separate. Credential entry, CAPTCHA handling,
and application-content verification require their own explicit policy. The
mechanics never establish account identity or content access themselves. Private
diagnostic images and session state must remain outside logs and repositories.

Profile preparation and shutdown helpers in `signin_window.automation.profiles`
refuse to steal a live or foreign browser's profile. `OwnedBrowserProcess`
captures an owned child through a Linux pidfd, so cleanup cannot signal a reused
PID. Hold the shared profile lease before preparation and through browser exit.
These helpers and native pointer input require Linux; importing the base window
and relay APIs does not import them.

When adopting an existing maintenance system, retain its session formats,
attempt-ledger files, holds and profile paths. Upgrade all processes sharing a
profile together if their lease naming changes. Rehearse with synthetic state
and test successful reuse, interrupted work, stale candidates and concurrent
writers. No helper automatically acknowledges a hold or resets an attempt budget.

## Install

```sh
pip install signin-window
```

Python 3.11 or later. The login service runs on Linux with `Xvfb`, `x11vnc`, noVNC 1.5 or later (its static files)
and a browser; [`examples/minimal/Dockerfile`](examples/minimal/Dockerfile) builds one. Use Debian trixie's Xvfb and
x11vnc (CI runs the end-to-end check there): on Ubuntu 24.04's, the live view showed the window but no click or key
reached it.

## The login service

A runner gets a `Window`. It opens the sign-in page on the window's display, calls `window.waiting(host)` once the
page is up (the live view opens only then), and returns the session when the site has signed the person in:

```python
import asyncio

from playwright.async_api import async_playwright
from signin_window.browser import LAUNCH_ARGS, harden
from signin_window.hosts import allowed, host_resolver_rules
from signin_window.service import Windows, build_app

HOSTS = ("example.com",)


async def sign_in(window):
    async with async_playwright() as p:
        context = await p.chromium.launch_persistent_context(
            window.temp_profile(),
            headless=False,
            env=window.env(),
            no_viewport=True,
            args=[f"--host-resolver-rules={host_resolver_rules(HOSTS)}", "--window-position=0,0", *LAUNCH_ARGS],
        )
        await harden(context)
        await context.route("**/*", lambda r: r.continue_() if allowed(r.request.url, HOSTS) else r.abort())
        page = await context.new_page()
        await page.goto("https://www.example.com/signin")
        window.waiting("example.com")
        while not window.cancelled.is_set():
            cookies = await context.cookies()
            if any(c["name"] == "session" for c in cookies):
                return {"cookies": cookies}  # handed over to the server, once
            await asyncio.sleep(1)


app = build_app(Windows(sign_in), token=TOKEN, novnc_dir="/opt/novnc")
```

[`examples/minimal/login_service.py`](examples/minimal/login_service.py) is the complete version.

### Locking the browser down

The window is a real browser in front of a person: `signin_window.browser` makes it show the site's sign-in and
nothing else.

- `LAUNCH_ARGS` (kiosk mode): no address bar, tabs, menus or window frame, and every window fills the display (which
  has no window manager). DevTools stay closed.
- `POLICY`, Chromium's managed policy: the image installs it as root (`python -m signin_window.browser
  install-policy`; `check-policy` tests for it, and `policy_installed()` lets a service refuse to open a window
  without it). Chromium does not offer to save passwords or fill addresses and cards, and opens no local files,
  file dialogs, downloads, printing, browser sign-in or sync; its own pages (new tab, history, settings) and `file:`,
  `data:` and `view-source:` addresses are blocked.
- `harden(context)` (`harden_sync` for Playwright's sync API): closes a tab or window opened with Ctrl+T or Ctrl+N.
  Kiosk mode reaches the windows of a persistent context only: for `browser.new_context()`, call
  `harden(context, browser)`, which makes its windows full screen (kiosk mode keeps them so) and closes windows
  opened outside it.

None of this changes what a page sees of the browser, so a site may still offer a passkey, which cannot work in a
remote window. Removing WebAuthn from the pages would hide the offer, but a Chrome without it contradicts itself where
sign-in pages' bot checks look; DevTools' WebAuthn environment keeps it but makes sites show a passkey button instead.

`scripts/browser_check.py` checks all of it in a real Chromium; CI runs it on every change. In your route check, tell
the page's own address from what it loads with `hosts.top_level(request)`: Playwright has no frame yet for a popup's
first page, and asking for it raises.

A window ends in one of two ways:

- **Hand-over**: the runner returns the session. It waits up to five minutes to be taken, once, by the server, then
  it is dropped. The login service keeps nothing.
- **Kept**: the runner keeps the session itself (a browser profile it refreshes, a snapshot it writes for the server
  to read) and calls `window.finish("connected")`, or another final state of its own such as `"wrong_account"`.
  `window.report(account=...)` adds public fields to the window's state. Once the person is signed in, call
  `window.saving()` while you keep the session: the live view closes and closing the window no longer interrupts
  you. Pass a `lock` to `Windows` if a keeper uses the same profile, and `windows.close_key(key)` closes every
  window of an account you remove.

A runner can be a plain function too (it runs in a thread and should watch `window.cancelled`), or a command:
`signin_window.child.run_child(window, argv)` runs it on the window's display and follows its progress lines
(`SIGNIN {"state": "waiting"}` ... `SIGNIN {"state": "signed_in", ...}`), which suits sign-in code that is
synchronous or someone else's.

For a child that keeps its own profile, use `run_child(window, argv, kept=True)`.
The child calls `signin_window.child.begin_saving()` before publication: this
blocks until the parent revokes remote control. After saving and confirmed
browser cleanup, it emits `emit(state="connected")` and exits 0. Both are
required; a `signed_in` payload is refused in this mode. No session crosses the
pipe. Set `stop_seconds` (default 5) to allow the child to restore its profile
after cancellation; set the host's save budget to cover its publication and
cleanup. The optional [LinkedIn prototype](examples/linkedin/README.md) uses
this boundary with upstream's existing display, profile lease and cookie format.

`Windows` options: `slots` (windows at a time, each with its own display), `minutes` (time limit), `xvfb` and
`x11vnc` (binaries), `lock` and `lock_wait`, `display_base` and `vnc_base` (window *n* uses display
`display_base + n` and VNC port `vnc_base + n` on loopback). `build_app` options: `start_params(body)` turns a start
request into the window's `params` (raise `ValueError` to refuse it; a `"key"` param makes a newer window for the
same key cancel the older), `title` for the plain view page, and `routes` of your own behind the bearer.

The service's API (`build_app`): `POST /logins`, `GET /logins/{id}`, `POST /logins/{id}/result` (the session, once),
`DELETE /logins/{id}`, `WS /logins/{id}/vnc?t=` (the live view, with the window's view token), `GET /view/{id}?t=`
(a plain page showing the window, for someone on the service's own network), `GET /novnc/...` and `GET /health`.
Shutting the service down closes its windows. `LoginClient.request(method, path)` calls a route of your own on it.

## The relay, in your server

```python
from signin_window.client import LoginClient
from signin_window.page import PageText
from signin_window.relay import Relay


def store(link, session):
    save_session(link.key, session["cookies"])  # yours
    return "connected"


relay = Relay(
    LoginClient("http://login:8080", TOKEN),
    "https://mcp.example.com/connect",
    text=PageText(service="Example", secure_host=r"(^|\.)example\.com$"),
    on_signed_in=store,
)
app.routes.extend(relay.routes("/connect"))  # outside your server's bearer

link = relay.create(account_id)  # in your connect tool
return {"url": link.url, "expires_at": link.expires_at}
```

A link works for `link_ttl` (20 minutes) and one successful sign-in, up to `max_starts` windows (a reload or "try
again" opens a new one); a newer link for the same key replaces it, and each key gets `links_per_hour` links. Its id
has 192 random bits; requests for ids that do not exist are counted per client address (from `X-Forwarded-For`, or
your `client_address`) and slowed long before guessing could matter, without ever locking a real link out.

Hooks run one at a time, in a worker thread:

- `on_signed_in(link, session) -> state`: check the session and store it for `link.key`. Return `"connected"`, or a
  state of your own the page has a message for (`"wrong_account"`, say). Anything else, or an exception, is
  `"failed"`.
- `on_ended(link, window_state) -> state`: the window ended without a hand-over. By default its state is kept when
  the page has a message for it (a kept session's `"connected"`), else `"failed"`.

- `before_start(link) -> state | None`: runs before each window opens. Return None to go on, or a state of your own
  to refuse (an invite code the person has not entered yet, say); it may add to `link.params`.

`link.show(name=...)` adds public fields to the link's state, which the page's messages can use (`{name}`).

`PageText` holds everything the page says (`{service}` and `{label}` work in all of it): `service`, `title`,
`help_html`, `intro_html`, `button`, `secure_host` (a host it matches gets a padlock), `starting`, `waiting`, `saving`, `outcomes` (state ->
message; `with_outcomes(...)` adds your own) and `script_extra` (it may define `window.signinBeforeStart`, an async
function that must return true before a window opens, for an invite code the person enters first, say).
`auto_start=True` opens the window as the page loads, without the intro and its button (a reloaded `reconnect` page
still resumes its attempt). Use it only for a link the host has bound to the signed-in person who just asked for it;
a link handed to someone keeps the intro, which tells them whose account it connects.

The relay talks to the login service through `LoginClient`; any object with the same methods (`Backend`) works,
for a login service of another shape.

## Security

- The login service never faces the internet: put it on a private network with your server. Every route but
  `/health`, noVNC's files and the person's own view needs its bearer (32+ characters); a window's live view needs
  that window's view token, which only the caller that started it gets, and it is open only while the sign-in page
  is shown (`waiting`). The VNC server listens on loopback without a password; the service's WebSocket bridge is
  the only way in.
- A link's id is its credential. Pages are `no-store`, `no-referrer`, not framable, with a strict
  Content-Security-Policy; nothing in the link's state or page is ever the session.
- Keep the window on the site: `signin_window.hosts` checks every request against the site's hosts and makes every
  other host unresolvable for the browser, so neither a link on the page nor a redirect turns the window into a
  general browser. Lock the browser itself down too ("Locking the browser down"): no address bar, no Chromium pages,
  no local files.
- A hand-over session leaves the login service once, to your server's hook, and is dropped if nobody takes it.
- Passkeys do not work in a remote window (they need the person's own device nearby): people sign in with a
  password and a code, and Chromium never offers to keep the password (`POLICY`).

Report vulnerabilities privately ([SECURITY.md](SECURITY.md)).

## Development

```sh
make bootstrap   # uv sync --locked
make check       # lint, format, tests
uv sync --group browser && uv run playwright install chromium && uv run pytest tests/test_paste_dom.py
NOVNC_DIR=/opt/novnc uv run --group browser python scripts/e2e.py   # with Xvfb and x11vnc installed
sudo .venv/bin/python -m signin_window.browser install-policy && uv run --group browser python scripts/browser_check.py
```

`scripts/e2e.py` runs the whole path with real browsers and a stand-in site: a link, its live view, paste, a
hand-over and closing the page; CI runs it on every change.

## License

MIT


### Shared authentication mechanics

The optional `signin_window.automation.google.GoogleIdentityDriver` supplies a
bounded Google sign-in flow through injected browser and secret-filler contracts.
Configure its exact controls, observations, allowed origins and callback check;
provide a narrowly scoped credential backend explicitly. It reports actions it
actually observed. A completed identity callback never proves application access.

`automation.secret_filler.OpSecretFiller` is an optional 1Password adapter. It
checks the top-level origin before and after resolving each field and binds
application to an exact frame/document. `automation.secrets.OpSecretReader` uses
only the identity supplied by its caller; a failed read never obtains a different
identity. Without an explicit token it uses the environment's: a 1Password
Connect server (`OP_CONNECT_HOST` and `OP_CONNECT_TOKEN`, which `op` prefers)
or else `OP_SERVICE_ACCOUNT_TOKEN`, and passes `op` only that identity. No human window API imports these modules or reads credentials.

For a maintenance process that owns a persistent Chromium profile, install
`signin-window[chromium]` and run `patchright install --with-deps chromium`.
`automation.runtime.virtual_display()` allocates an isolated Xvfb display.
While holding the application's durable profile lease, use
`automation.runtime.open_browser(profile, display=display)` for the browser's
lifetime. Its facade supplies origin-bound fills, observations and native X11
input. It preserves the profile, refuses foreign owners and uses a pidfd to bind
shutdown to the exact browser it launched. An application still owns network
allowlists, identity checks, holds, budgets, publication and scheduling.

Human runners that create their own context can use
`signin_window.browser.browser_environment(window.env())` to pass only browser
runtime settings to Chromium. Operator tokens, planner credentials and ambient
proxy variables are excluded. An authorized maintenance runner can also reuse
`automation.runtime.close_owned_browser` after capturing its own process; it
never guesses ownership or deletes a profile.

### Supported maintenance integration APIs

Applications use `sessions.AttemptBudget`, `sessions.WarmFirst`, the public
`leases` and `state` functions, and the optional `automation` modules. Names
starting with an underscore are implementation details. Consumers should test
against an installed release rather than importing those details.

`automation.maintenance.MaintenanceStateStore` supplies atomic holds,
compare-and-clear, escalating cooldown persistence and publication watermarks.
Supply your existing state/hold/cooldown models, allowed keys, cooldown durations
and error type. The application's schema and policy remain authoritative; loading
an existing file never rewrites it or resets attempts or holds.

`automation.secrets.CredentialReader` has two members: a side-effect-free
`available: bool` property and `read_field(reference, *, field) -> str`, where
`field` is `username`, `password` or `totp`. References are opaque to the generic
layer. `automation.secret_filler.CredentialFiller(reader=...)` delivers fields
just in time and checks the allowed origin both before and after resolution.
Backend errors are redacted and never trigger a fallback to another identity.
`OpCredentialReader` and `OpSecretFiller` retain the 1Password implementation.

`configured_credential_filler("example_backend:create_reader")` loads an explicit
zero-argument factory returning that interface. Treat the module as trusted
operator-installed code; keep its credentials in runtime configuration. An empty
factory retains the existing 1Password default. Imports and availability checks
must not read a credential or contact a provider. Custom backends own field
mapping, secret-store authentication, and generated TOTP values.

Advanced challenge integrations may use the supported
`automation.hcaptcha.ChallengeActionBoundary`, `HCaptchaOutcomeObserver` and
`hcaptcha_instruction` seams. Applications still supply the planner and decide
whether the resulting session or content is acceptable.

## Optional browser identity

`pip install 'signin-window[oidc]'` adds a provider-neutral Authlib integration for
Starlette applications. The window and relay still need only the core package.
This integration can also protect native pairing and device-code pages without
opening a remote browser. Hosted browser session storage requires a POSIX host
with private file permissions; it is independent of an application's local stdio
support on other operating systems.

```python
from pathlib import Path

from signin_window.oidc import BrowserAuth, OIDCConfig
from starlette.applications import Starlette

auth = BrowserAuth(OIDCConfig(
    issuer="https://identity.example.com",
    client_id="example-connections",
    public_url="https://connections.example.com",
    state_dir=Path("/private/browser-sessions"),
    cookie_name="__Host-example-connections",
    required_group="example-users",
    claim_names=("account_alias",),
))
app = auth.middleware(Starlette(routes=auth.routes()))
```

Register exactly `<public_url>/connections/callback` with the provider and add
your application's home/status/start/disconnect routes. Configure `client_secret`
from protected runtime configuration for a confidential client; omitting it uses
public-client PKCE. Every exchange also validates state, nonce, issuer, audience
and expiry. Callbacks are single-use even across application workers.

`auth.identity(request)` returns `None` or a verified dictionary containing
`issuer`, `sub`, `name`, `groups`, `claims` and `expires`. Only explicitly selected
custom claims are retained. Map that identity to an existing account in your
application; groups alone do not confer ownership. Neither browser input nor a
forwarded header establishes a connection owner. Supply that policy through
`Relay(authorize=...)`, protecting every route and the live viewer.

The browser holds an opaque Secure/HttpOnly/SameSite cookie with no Domain
attribute. Private server-side sessions last at most 15 minutes. Provider
tokens are discarded after callback verification. Sign-out is an exact-origin
POST and ends this local browser session; it does not revoke provider credentials
or agent permissions. It answers with a signed-out page rather than the connections
home, so a host that sends signed-out visitors straight to sign-in does not sign
them back in through the provider's own session. Use separate origins for applications with different trust
boundaries; cookie names and URL paths do not provide browser-origin isolation.

For account replacement, `/connections/login?reauth=1` requests fresh provider
authentication. A successful, verified fresh `auth_time` produces a server-owned
`reauthenticated_at` value in the identity. An ordinary sign-in whose verified
`auth_time` is at most `RECENT_AUTHENTICATION_SECONDS` (300) old sets it to that
`auth_time`, so a person who has just authenticated is not asked again; an older
provider session, or a missing or future `auth_time`, leaves it unset. Applications decide how recently that
must have occurred before a sensitive action. Safe `next` destinations are the
connections home or a local `/connect/<id>` attempt, including a configured base
path. Test-only loopback HTTP must be explicitly enabled in `OIDCConfig`; it uses
a different cookie name.

Connections responses receive a restrictive default Content Security Policy.
An application redirecting a submitted form to its native provider may supply its
own complete policy, allowing only that fixed provider origin in `form-action`.
The middleware preserves that policy without appending a conflicting second one;
it still supplies no-store and the other browser safety headers. Never derive a
policy from browser input.

Applications retain credential publication, provider-account verification and
durable disconnect controls. Keep those controls independent of browser sessions
and check them in actual credential writers and maintenance workers, including
after restart or removal of the browser UI configuration.
