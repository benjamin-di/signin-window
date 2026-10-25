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
private writes; `signin_window.leases` provides ordered session, attempt and
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
            window.temp_profile(), headless=False, env=window.env(), no_viewport=True,
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
                return {"cookies": cookies}          # handed over to the server, once
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
app.routes.extend(relay.routes("/connect"))   # outside your server's bearer

link = relay.create(account_id)               # in your connect tool
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
