"""The page a sign-in link opens: what it says (``PageText``) and the page itself (``render``).

The page explains what is about to happen, opens a window when the person continues, shows it through noVNC once the
sign-in page is up, follows the window until it ends and says how it ended. All its text is yours to change;
``{service}`` and ``{label}`` in it are replaced (escaped) by the service's name and the link's label. In the
outcome messages, ``{name}`` is replaced in the browser by the escaped public field ``name`` of the link's state
(what your relay hooks ``show``).
"""

from __future__ import annotations

import html
import json
from dataclasses import dataclass, field

DEFAULT_OUTCOMES = {
    "connected": "<p class=ok>✓</p><h1>Connected</h1><p>You can close this page and go back to your assistant.</p>",
    "busy": "<h1>Someone else is signing in right now</h1><p>Please try again in a few minutes.</p>",
    "failed": "<h1>Something went wrong</h1><p>Nothing was saved.</p>",
    "cancelled": "<h1>Cancelled</h1>",
    "expired": "<h1>This link has expired</h1><p>Sign-in links work once, for a short time. Ask for a new one.</p>",
    "limited": "<h1>Too many tries</h1><p>Please wait ten minutes and try again.</p>",
}
NO_RETRY = ("connected", "expired", "limited")


@dataclass(frozen=True)
class PageText:
    """What the page says. HTML fields are trusted (they come from your code, never from a request)."""

    service: str = "the site"
    title: str = "Connect your {service} account"
    help_html: str = (
        "Sign in on {service}'s own page below, as you usually do (passkeys do not work in this window). Pasting "
        "works too. The page runs in a browser on the server your assistant uses."
    )
    intro_html: str = (
        "This link connects {service} for <b>{label}</b>. Continue only if that is you: whoever signs in here, their "
        "account is the one that will be used."
    )
    button: str = "Continue to {service}'s sign-in"
    #: A JavaScript regular expression: a host it matches is shown with a padlock.
    secure_host: str = ""
    host_label: str = ""
    starting: str = "Opening {service}…"
    waiting: str = "Sign in as you usually do. This page notices when you're in."
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
        body = f"<main class=msg>{text.html(text.outcomes.get('expired', DEFAULT_OUTCOMES['expired']))}</main>"
        return (
            _PAGE.replace("{{TITLE}}", html.escape(text.plain(text.title)))
            .replace("{{BODY}}", body)
            .replace("{{SCRIPT}}", "")
        )
    body = (
        _BODY.replace("{{HEADING}}", html.escape(text.plain(text.title)))
        .replace("{{HELP}}", text.html(text.help_html, label))
        .replace("{{HOST}}", html.escape(text.plain(text.host_label)))
        .replace("{{INTRO}}", text.html(text.intro_html, label))
        .replace("{{BUTTON}}", html.escape(text.plain(text.button)))
    )
    config = {
        "text": {"starting": text.plain(text.starting), "waiting": text.plain(text.waiting)},  # set as text
        "outcomes": {state: text.html(message, label) for state, message in text.outcomes.items()},
        "noRetry": list(text.no_retry),
        "secureHost": text.secure_host,
        "frameTitle": text.plain(text.title),
    }
    # JSON in a script element: "</" would end it, so it is escaped.
    script = (
        (f"<script>{text.script_extra}</script>\n" if text.script_extra else "")
        + "<script>const CONFIG = "
        + json.dumps(config).replace("</", "<\\/")
        + ";</script>\n"
        + _SCRIPT
    )
    return (
        _PAGE.replace("{{TITLE}}", html.escape(text.plain(text.title)))
        .replace("{{BODY}}", body)
        .replace("{{SCRIPT}}", script)
    )


_BODY = """<header><h1>{{HEADING}}</h1>
<p>{{HELP}}</p>
<div class=bar hidden><span id=host>{{HOST}}</span><span id=status></span></div></header>
<main id=intro class=msg><p>{{INTRO}}</p>
<button id=go>{{BUTTON}}</button></main>
<div id=view></div>
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
header p{margin:0 0 8px;font-size:13px;color:#4b4b4b;max-width:62em}
.bar{display:flex;justify-content:space-between;gap:12px;font-size:13px}
#host{color:#1a7f37;font-weight:600}#status{color:#4b4b4b;text-align:right}
#view{flex:1;min-height:0;display:flex}
#view iframe{flex:1;border:0;width:100%;height:100%;background:#fff}
.msg{margin:auto;padding:28px 20px;text-align:center;max-width:26em;width:100%;box-sizing:border-box}
.msg h1{font-size:22px}.ok{font-size:44px;color:#1a7f37;margin:0}
button{font:inherit;font-weight:600;margin-top:14px;width:100%;padding:12px 18px;border-radius:8px;
 border:1px solid #141414;background:#141414;color:#fff}
input{font:inherit;width:100%;box-sizing:border-box;padding:10px;margin-top:10px;border:1px solid #999;
 border-radius:6px}
[hidden]{display:none!important}
@media (max-width:600px){header p{font-size:12px}}
</style>
{{BODY}}
{{SCRIPT}}
</html>"""

_SCRIPT = """<script>
const base = location.pathname.replace(/\\/+$/, "");
const $ = id => document.getElementById(id);
const esc = t => String(t ?? "").replace(/[&<>"']/g, c => `&#${c.charCodeAt(0)};`);
const post = (path, data) => fetch(`${base}/${path}`, {method: "POST", headers: {"content-type": "application/json"},
                                                      body: JSON.stringify(data || {})}).then(r => r.json());
const AGAIN = `<button onclick="location.reload()">Try again</button>`;
const secure = CONFIG.secureHost ? new RegExp(CONFIG.secureHost) : null;
function outcome(s) {
  const template = CONFIG.outcomes[s.state];
  if (template === undefined) return null;
  const filled = template.replace(/\\{([a-z_][a-z0-9_]*)\\}/g, (m, name) => esc(s[name]));
  return filled + (CONFIG.noRetry.includes(s.state) ? "" : AGAIN);
}
function finish(html) {
  $("view").hidden = true;
  $("intro").hidden = true;
  document.querySelector("header .bar").hidden = true;
  const done = $("done"); done.innerHTML = html; done.hidden = false;
}
let viewer = false, over = false;
function show(s) {
  const ended = outcome(s);
  if (ended !== null) {
    over = true;
    finish(ended);
    return true;
  }
  if (s.host) $("host").textContent = (secure && secure.test(s.host) ? "🔒 " : "") + s.host;
  $("status").textContent = CONFIG.text[s.state] || "";
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
  try {
    const r = await fetch(`${base}/state`, {cache: "no-store"});
    if (show(await r.json())) return;
  } catch (e) {}
  setTimeout(poll, 1500);
}
async function begin() {
  if (window.signinBeforeStart && !(await window.signinBeforeStart())) return;
  $("intro").hidden = true;
  document.querySelector("header .bar").hidden = false;
  $("status").textContent = CONFIG.text.starting;
  const layout = Math.min(innerWidth, screen.width) < 700 ? "phone" : "desktop";
  try {
    if (show(await post("start", {layout}))) return;
  } catch (e) {}
  poll();
}
$("go").addEventListener("click", begin);
addEventListener("pagehide", () => { if (!over && navigator.sendBeacon) navigator.sendBeacon(`${base}/cancel`); });
</script>"""
