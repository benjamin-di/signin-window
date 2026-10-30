"""The page a sign-in link opens: what it says (``PageText``) and the page itself (``render``).

The page explains what is about to happen, opens a window when the person continues, shows it through noVNC once the
sign-in page is up, follows the window until it ends and says how it ended. All its text is yours to change;
``{service}`` and ``{label}`` anywhere in it are replaced (escaped) by the service's name and the link's label (what
it signs in: an account, a site). In the
outcome messages, ``{name}`` is replaced in the browser by the escaped public field ``name`` of the link's state
(what your relay hooks ``show``).
"""

from __future__ import annotations

import html
import json
from dataclasses import dataclass, field

DEFAULT_OUTCOMES = {
    "connected": (
        "<p class=ok>✓</p><h1>Connection saved</h1><p>You can close this page and return to your assistant.</p>"
    ),
    "busy": "<h1>A sign-in is already open</h1><p>Continue that sign-in, or try again in a few minutes.</p>",
    "failed": (
        "<h1>We could not confirm the connection</h1>"
        "<p>Check the connection status before starting another sign-in.</p>"
    ),
    "unavailable": "<h1>This request is unavailable</h1><p>Return to your application to sign in or check access.</p>",
    "cancelled": "<h1>Sign-in cancelled</h1><p>Return to your connections to check the current status.</p>",
    "expired": "<h1>This link has expired</h1><p>Return to your connections to start a new sign-in.</p>",
    "limited": "<h1>Too many sign-in attempts</h1><p>Wait before starting another sign-in.</p>",
}
NO_RETRY = ("connected", "expired", "limited")


@dataclass(frozen=True)
class PageText:
    """What the page says. HTML fields are trusted (they come from your code, never from a request)."""

    service: str = "the site"
    title: str = "Connect your {service} account"
    help_html: str = (
        "Sign in to {service} in the remote browser below. Use a password or verification code; device passkeys "
        "do not work in this window. You can paste text with Ctrl+V or Cmd+V."
    )
    intro_html: str = "Connect {service} for <b>{label}</b>. Sign in to the account you want this application to use."
    button: str = "Continue to {service}'s sign-in"
    #: A JavaScript regular expression: a host it matches is shown with a padlock.
    secure_host: str = ""
    host_label: str = ""
    starting: str = "Opening {service}…"
    waiting: str = "Finish signing in below. We will check when you are done."
    saving: str = "Sign-in complete. Saving your connection…"
    #: Keep an active attempt on reload. Requires the host's relay/window lifespans.
    reconnect: bool = False
    #: Open the window as the page loads, without the intro and its button. Only for a link the host has already
    #: bound to the signed-in person, who has just asked for it; a link handed to someone keeps the intro.
    auto_start: bool = False
    return_url: str = ""

    def __post_init__(self):
        if self.return_url and (
            not self.return_url.startswith("/")
            or self.return_url.startswith("//")
            or "\\" in self.return_url
            or any(ord(c) < 32 for c in self.return_url)
        ):
            raise ValueError("return_url must be a local absolute path")

    #: State -> HTML shown when the link ends in that state; your own final states go here too.
    outcomes: dict[str, str] = field(default_factory=lambda: dict(DEFAULT_OUTCOMES))
    #: States whose message offers "Try again".
    no_retry: tuple[str, ...] = NO_RETRY
    #: Trusted JavaScript run before the page script; it may define ``window.signinBeforeStart``, an async function
    #: that returns true to go on with the sign-in (for a code the person enters first, say).
    script_extra: str = ""

    def with_outcomes(self, **outcomes: str) -> PageText:
        """A copy with more (or other) outcome messages."""
        from dataclasses import replace

        return replace(self, outcomes={**self.outcomes, **outcomes})

    def plain(self, text: str, label: str = "") -> str:
        """A text field with ``{service}`` and ``{label}`` in it (to be escaped where it is put)."""
        return text.replace("{service}", self.service).replace("{label}", label)

    def html(self, markup: str, label: str = "") -> str:
        """An HTML field with ``{service}`` and ``{label}`` in it, escaped."""
        return markup.replace("{service}", html.escape(self.service)).replace("{label}", html.escape(label))


def render(text: PageText, label: str | None) -> str:
    """The link's page; ``label`` None is the expired page."""
    if label is None:
        back = (
            f'<p><a class=button href="{html.escape(text.return_url, quote=True)}">Back to Connections</a></p>'
            if text.return_url
            else "<p>Ask your application for a new sign-in link.</p>"
        )
        body = f"<main class=msg>{text.html(text.outcomes.get('expired', DEFAULT_OUTCOMES['expired']))}{back}</main>"
        title = text.plain(text.title.replace(" {label}", "")).strip()  # no link, no label
        return _PAGE.replace("{{TITLE}}", html.escape(title)).replace("{{BODY}}", body).replace("{{SCRIPT}}", "")
    body = (
        _BODY.replace("{{HEADING}}", html.escape(text.plain(text.title, label)))
        .replace("{{HELP}}", text.html(text.help_html, label))
        .replace("{{HOST}}", html.escape(text.plain(text.host_label, label)))
        .replace("{{INTRO}}", text.html(text.intro_html, label))
        .replace("{{BUTTON}}", html.escape(text.plain(text.button, label)))
    )
    config = {
        "text": {
            "starting": text.plain(text.starting, label),
            "waiting": text.plain(text.waiting, label),
            "saving": text.plain(text.saving, label),
            "checking": "Checking the connection…",
        },
        "outcomes": {state: text.html(message, label) for state, message in text.outcomes.items()},
        "noRetry": list(text.no_retry),
        "secureHost": text.secure_host,
        "frameTitle": text.plain(text.title, label),
        "reconnect": text.reconnect,
        "autoStart": text.auto_start,
        "returnUrl": text.return_url,
    }
    # JSON in a script element: "</" would end it, so it is escaped.
    script = (
        (f"<script>{text.script_extra}</script>\n" if text.script_extra else "")
        + "<script>const CONFIG = "
        + json.dumps(config).replace("</", "<\\/")
        + ";</script>\n"
        + _SCRIPT
    )
    title = html.escape(text.plain(text.title, label))
    return _PAGE.replace("{{TITLE}}", title).replace("{{BODY}}", body).replace("{{SCRIPT}}", script)


_BODY = """<header><h1>{{HEADING}}</h1>
<p>{{HELP}}</p>
<div class=bar hidden><span id=host>{{HOST}}</span><span id=status role=status aria-live=polite></span></div></header>
<main id=intro class=msg><p>{{INTRO}}</p>
<button id=go>{{BUTTON}}</button></main>
<div id=view></div>
<p id=recovery role=status hidden></p>
<main id=done class=msg hidden></main>"""

_PAGE = """<!doctype html><html lang=en><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name=referrer content=no-referrer>
<title>{{TITLE}}</title>
<style>
:root{color-scheme:light;font:15px/1.45 system-ui,-apple-system,"Segoe UI",sans-serif;color:#141414}
html,body{margin:0;height:100%;background:#f4f4f4}
body{display:flex;flex-direction:column}
header{padding:12px 16px 8px;background:#fff;border-bottom:1px solid #ddd}
h1{font-size:18px;margin:0 0 4px}
header p{margin:0 0 8px;font-size:14px;color:#4b4b4b;max-width:62em}
.bar{display:flex;justify-content:space-between;gap:12px;font-size:13px}
#host{color:#1a7f37;font-weight:600}#status{color:#4b4b4b;text-align:right}
#view{flex:1;min-height:0;display:flex}
#view iframe{flex:1;border:0;width:100%;height:100%;background:#fff}
.msg{margin:auto;padding:28px 20px;text-align:center;max-width:26em;width:100%;box-sizing:border-box}
.msg h1{font-size:22px}.ok{font-size:44px;color:#1a7f37;margin:0}
button,.button{font:inherit;font-weight:600;margin-top:14px;min-height:44px;padding:12px 18px;border-radius:8px;
 border:1px solid #141414;background:#141414;color:#fff}
.msg button,.msg .button{display:inline-block;width:100%;box-sizing:border-box;text-decoration:none}
header button{font-size:14px;margin:8px 0}
a:focus-visible,button:focus-visible{outline:3px solid #a35d00;outline-offset:3px}
#recovery{margin:0;padding:12px 16px;background:#fff3d9;color:#5d400a}#recovery button{margin:4px 8px;font-size:14px}
input{font:inherit;width:100%;box-sizing:border-box;padding:10px;margin-top:10px;border:1px solid #999;
 border-radius:6px}
[hidden]{display:none!important}
@media (max-width:600px){header p{font-size:14px}.bar{flex-wrap:wrap}#status{text-align:left}}
</style>
{{BODY}}
{{SCRIPT}}
</html>"""

_SCRIPT = """<script>
const base = location.pathname.replace(/\\/+$/, "");
const $ = id => document.getElementById(id);
const esc = t => String(t ?? "").replace(/[&<>"']/g, c => `&#${c.charCodeAt(0)};`);
async function request(path, options = {}, allowEmpty = false) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10000);
  try {
    const response = await fetch(`${base}/${path}`, {...options, cache: 'no-store', redirect: 'manual',
                                                   signal: controller.signal});
    // Application refusals carry useful, finite outcomes too (for example limited or unavailable).
    if ([401, 403].includes(response.status) || response.type === 'opaqueredirect') {
      const error = new Error('request'); error.status = response.status;
      if (response.type === 'opaqueredirect') error.status = 401;
      throw error;
    }
    if (allowEmpty && response.status === 204) return null;
    let result;
    try { result = await response.json(); }
    catch (_) { const error = new Error('response'); error.status = response.status; throw error; }
    if (!result || typeof result.state !== 'string' ||
        !['ready', 'new', 'starting', 'waiting', 'saving', 'checking'].includes(result.state) &&
        !Object.hasOwn(CONFIG.outcomes, result.state)) throw new Error('state');
    if (!response.ok && !Object.hasOwn(CONFIG.outcomes, result.state)) throw new Error('response');
    return result;
  } finally { clearTimeout(timeout); }
}
const post = (path, data) => request(path, {method: "POST", headers: {"content-type": "application/json"},
                                         body: JSON.stringify(data || {})});
const AGAIN = `<button onclick="location.reload()">Try again</button>`;
const secure = CONFIG.secureHost ? new RegExp(CONFIG.secureHost) : null;
function outcome(s) {
  if (!Object.hasOwn(CONFIG.outcomes, s.state)) return null;
  const template = CONFIG.outcomes[s.state];
  const filled = template.replace(/\\{([a-z_][a-z0-9_]*)\\}/g, (m, name) => esc(s[name]));
  return filled + (CONFIG.noRetry.includes(s.state) ? "" : AGAIN);
}
function finish(html) {
  if (over) return;
  over = true;
  clearTimeout(pollTimer);
  $("recovery").hidden = true;
  $("view").hidden = true;
  $("intro").hidden = true;
  document.querySelector("header .bar").hidden = true;
  const done = $("done"); done.innerHTML = html; done.hidden = false;
  if (CONFIG.returnUrl) {
    const back = document.createElement("a"); back.href = CONFIG.returnUrl;
    back.textContent = "Back to Connections"; back.className = "button"; done.appendChild(back);
  }
  const heading = done.querySelector("h1");
  if (heading) { heading.tabIndex = -1; heading.focus(); }
}
let viewer = false, over = false, failures = 0, pollTimer, cancellationUncertain = false;
function recover(error) {
  if (over) return true;
  if ([401, 403].includes(error.status)) {
    finish('<h1>Sign in to Connections again</h1><p>Your browser sign-in expired or no longer has access. '
           + 'Return to your connections to check the sign-in status.</p>');
    return true;
  }
  if ([404, 410].includes(error.status)) {
    finish(CONFIG.outcomes.expired); return true;
  }
  return false;
}
function pause(message, cancellation = false) {
  if (over || cancellationUncertain && !cancellation) return;
  cancellationUncertain = cancellation;
  const area = $("recovery"); area.replaceChildren(document.createTextNode(message + ' ')); area.hidden = false;
  const retry = document.createElement('button'); retry.textContent = 'Check sign-in status';
  retry.addEventListener('click', () => {
    failures = 0; cancellationUncertain = false; area.hidden = true; clearTimeout(pollTimer); poll();
  });
  area.appendChild(retry);
}
function show(s) {
  if (over) return true;
  if (!cancellationUncertain) $("recovery").hidden = true;
  const ended = outcome(s);
  if (ended !== null) {
    finish(ended);
    return true;
  }
  if (s.state !== 'ready' && s.state !== 'new') {
    $("intro").hidden = true;
    document.querySelector("header .bar").hidden = false;
  }
  if (s.host) $("host").textContent = (secure && secure.test(s.host) ? "🔒 " : "") + s.host;
  $("status").textContent = CONFIG.text[s.state] || "";
  if (s.state === "saving") { $("view").replaceChildren(); viewer = false; }
  if (s.state === "waiting" && !viewer) {
    viewer = true;
    const frame = document.createElement("iframe");
    const q = new URLSearchParams({autoconnect: 1, resize: "scale", reconnect: 1, reconnect_delay: 1500,
                                   path: "../vnc", show_dot: 1});  // relative to the viewer's own address
    frame.src = `${base}/novnc/vnc.html?${q}`;
    frame.title = CONFIG.frameTitle;
    frame.allow = "clipboard-read";
    $("view").appendChild(frame);
  }
  return false;
}
async function poll() {
  clearTimeout(pollTimer);
  if (over) return;
  try {
    if (show(await request('state'))) return;
    failures = 0;
  } catch (error) {
    if (recover(error)) return;
    failures += 1;
    $("status").textContent = 'We could not check your progress. Trying again…';
    if (failures >= 3) {
      pause('We cannot check your progress right now. Your sign-in may still be running.');
      return;
    }
  }
  pollTimer = setTimeout(poll, Math.min(1500 * 2 ** failures, 6000));
}
async function begin() {
  if (window.signinBeforeStart && !(await window.signinBeforeStart())) return;
  $("intro").hidden = true;
  document.querySelector("header .bar").hidden = false;
  $("status").textContent = CONFIG.text.starting;
  const layout = Math.min(innerWidth, screen.width) < 700 ? "phone" : "desktop";
  try {
    if (show(await post("start", {layout}))) return;
  } catch (error) { if (recover(error)) return; }
  poll();
}
$("go").addEventListener("click", begin);
const cancel = document.createElement("button");
cancel.textContent = "Cancel sign-in";
cancel.hidden = true;
document.querySelector("header").appendChild(cancel);
cancel.addEventListener("click", async () => {
  cancel.disabled = true;
  try {
    const result = await request('cancel', {method: 'POST'}, true);
    if (over || (result && show(result))) return;
    const state = await request('state');
    if (!over && !show(state)) poll();
  } catch (error) {
    if (!over && !recover(error))
      pause('We could not confirm the cancellation. Check the sign-in status before trying again.', true);
  } finally { cancel.disabled = false; }
});
if (CONFIG.reconnect) {
  (async () => {
    const s = await request('state');
    if (s.state !== "ready") {
      $("intro").hidden = true;
      document.querySelector("header .bar").hidden = false;
      if (!show(s)) poll();
    } else if (CONFIG.autoStart) begin();
  })().catch(error => {
    if (!recover(error)) pause('We could not load your sign-in status. Check its status before starting again.');
  });
  setInterval(() => {
    cancel.hidden = over || $("intro").hidden === false || $("status").textContent === CONFIG.text.saving;
  }, 250);
} else {
  addEventListener("pagehide", () => { if (!over && navigator.sendBeacon) navigator.sendBeacon(`${base}/cancel`); });
  if (CONFIG.autoStart) begin();
}
</script>"""
