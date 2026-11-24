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
import re
from dataclasses import dataclass, field

from ._identity import stamp
from .connections import PageIdentity

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
        "do not work in this window. On a phone, tap a remote field then Paste to paste directly, or tap Keyboard "
        "to type. Drag to pan when zoomed or when the keyboard is open, or use two fingers to scroll the remote "
        "page. On a computer, you can also paste with Ctrl+V or Cmd+V."
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

    #: Optional host application identity, also shown on expired and unavailable pages.
    identity: PageIdentity | None = None
    #: Optional concise inline guidance shown while the remote window is active (plain text, escaped).
    notice: str = ""

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


def _fill_slots(template: str, slots: dict[str, str]) -> str:
    return re.sub(r"\{\{(" + "|".join(slots) + r")\}\}", lambda match: slots[match.group(1)], template)


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
        return stamp(
            _fill_slots(_PAGE, {"TITLE": html.escape(title), "BODY": body, "SCRIPT": ""}),
            text.identity,
        )
    body = _fill_slots(
        _BODY,
        {
            "HEADING": html.escape(text.plain(text.title, label)),
            "HELP": text.html(text.help_html, label),
            "HOST": html.escape(text.plain(text.host_label, label)),
            "NOTICE": html.escape(text.plain(text.notice, label)),
            "INTRO": text.html(text.intro_html, label),
            "BUTTON": html.escape(text.plain(text.button, label)),
        },
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
        "notice": bool(text.notice.strip()),
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
    return stamp(_fill_slots(_PAGE, {"TITLE": title, "BODY": body, "SCRIPT": script}), text.identity)


_BODY = """<header><div class=heading><h1>{{HEADING}}</h1>
<div class=bar hidden><span id=host>{{HOST}}</span><span id=status role=status aria-live=polite></span></div></div>
<details id=signin-help><summary aria-label="Sign-in help">?</summary><div>{{HELP}}</div></details></header>
<p id=notice hidden>{{NOTICE}}</p>
<div id=layout-mismatch role=status hidden><span id=layout-mismatch-text></span>
<button type=button id=layout-switch></button></div>
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
html,body{margin:0;height:100%;background:#f4f4f4;overflow:hidden}
body{display:flex;flex-direction:column;height:var(--signin-viewport-height,100dvh)}
header{position:relative;flex-shrink:0;display:flex;align-items:center;gap:6px;padding:6px 10px 6px 16px;
 background:#fff;border-bottom:1px solid #ddd}
.heading{flex:1;min-width:0}h1{font-size:16px;margin:0;overflow-wrap:anywhere}
.bar{font-size:12px}#host{color:#1a7f37}#status{display:block;color:#4b4b4b}
body.viewer-active #status:not(.warn){position:absolute;width:1px;height:1px;overflow:hidden;clip-path:inset(50%)}
#notice{flex-shrink:0;margin:0;padding:6px 16px;background:#f8f9fa;border-bottom:1px solid #e5e7eb;
 color:#4b5563;font-size:13px;line-height:1.35}
#layout-mismatch{flex-shrink:0;display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;
 padding:8px 16px;background:#eef4ff;border-bottom:1px solid #c7d9ff;color:#19396b;font-size:13px}
#layout-switch{margin:0;min-height:36px;padding:6px 12px;font-size:13px;border-radius:6px;
 border:1px solid #2358bd;background:#2358bd;color:#fff;cursor:pointer}
#signin-help summary{list-style:none;display:flex;align-items:center;justify-content:center;
 width:44px;height:44px;cursor:pointer;font-weight:700;border-radius:8px}
#signin-help summary::-webkit-details-marker{display:none}
#signin-help[open] summary{background:#eef2f3}
#signin-help>div{position:absolute;top:100%;right:12px;margin-top:4px;z-index:20;box-sizing:border-box;width:360px;
 max-width:calc(100vw - 24px);padding:16px;border:1px solid #ddd;border-radius:12px;background:#fff;
 box-shadow:0 8px 24px #0002;font-size:14px;max-height:60dvh;overflow:auto}
#view{flex:1;min-height:0;display:flex}
#view iframe{flex:1;border:0;width:100%;height:100%;background:#f4f4f4}
.msg{margin:auto;padding:28px 20px;text-align:center;max-width:26em;width:100%;box-sizing:border-box;overflow:auto}
.msg h1{font-size:22px}.ok{font-size:44px;color:#1a7f37;margin:0}
button,.button{font:inherit;font-weight:600;margin-top:14px;min-height:44px;padding:12px 18px;border-radius:8px;
 border:1px solid #141414;background:#141414;color:#fff;cursor:pointer}
.msg button,.msg .button{display:inline-block;width:100%;box-sizing:border-box;text-decoration:none}
header button{font-size:22px;margin:0;padding:4px;width:44px;height:44px;min-width:44px;
 background:transparent;color:#141414;border:0;font-weight:400;border-radius:8px}
header button:hover{background:#eef2f3}
a:focus-visible,button:focus-visible{outline:3px solid #a35d00;outline-offset:3px}
#recovery{margin:0;padding:12px 16px;background:#fff3d9;color:#5d400a}#recovery button{margin:4px 8px;font-size:14px}
input{font:inherit;width:100%;box-sizing:border-box;padding:10px;margin-top:10px;border:1px solid #999;
 border-radius:6px}
[hidden]{display:none!important}
</style>
{{BODY}}
{{SCRIPT}}
</html>"""

_SCRIPT = """<script>
const base = location.pathname.replace(/\\/+$/, "");
const $ = id => document.getElementById(id);
// iOS can shrink the visual viewport without resizing the layout viewport. Keep the iframe and its input in view.
function fitViewport() {
  if (window.visualViewport) {
    document.body.classList.toggle('keyboard-open', visualViewport.height < innerHeight * .8);
    document.documentElement.style.setProperty('--signin-viewport-height', `${visualViewport.height}px`);
  }
}
fitViewport();
if (window.visualViewport) visualViewport.addEventListener('resize', fitViewport);
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
const AGAIN = `<button type="button" data-retry>Try again</button>`;
const secure = CONFIG.secureHost ? new RegExp(CONFIG.secureHost) : null;
const desiredLayout = () => Math.min(innerWidth, screen.width) < 700 ? "phone" : "desktop";
let currentState = "ready", activeLayout = "", canRestart = false, closingActive = false;
let opGen = 0, cancelGen = 0, busyAction = false, restarting = false, pendingRestart = false;
function setActionDisabled(disabled) {
  restart.disabled = disabled;
  cancel.disabled = disabled;
  $("layout-switch").disabled = disabled;
}
function updateChrome() {
  const hideControls = over || $("intro").hidden === false || currentState === "saving";
  cancel.hidden = hideControls;
  restart.hidden = hideControls || !canRestart || closingActive || !["starting", "waiting"].includes(currentState);
  $("notice").hidden = !CONFIG.notice || !["starting", "waiting"].includes(currentState) || over || closingActive;
  const mismatch = !over && !busyAction && !closingActive && canRestart
    && ["starting", "waiting"].includes(currentState)
    && (activeLayout === "phone" || activeLayout === "desktop") && activeLayout !== desiredLayout();
  $("layout-mismatch").hidden = !mismatch;
  if (mismatch) {
    const target = desiredLayout();
    $("layout-mismatch-text").textContent = activeLayout === "phone"
      ? "This sign-in opened in mobile view." : "This sign-in opened in desktop view.";
    $("layout-switch").textContent = target === "desktop" ? "Switch to desktop view" : "Switch to mobile view";
  }
}
function outcome(s) {
  if (!Object.hasOwn(CONFIG.outcomes, s.state)) return null;
  const template = CONFIG.outcomes[s.state];
  const filled = template.replace(/\\{([a-z_][a-z0-9_]*)\\}/g, (m, name) => esc(s[name]));
  return filled + (CONFIG.noRetry.includes(s.state) ? "" : AGAIN);
}
function finish(html) {
  if (over) return;
  over = true;
  opGen += 1;
  clearTimeout(pollTimer);
  activeLayout = "";
  closingActive = false;
  pendingRestart = false;
  $("recovery").hidden = true;
  $("view").replaceChildren(); viewer = false;
  document.body.classList.remove('viewer-active');
  $("view").hidden = true;
  $("intro").hidden = true;
  document.querySelector("header .bar").hidden = true;
  const done = $("done"); done.innerHTML = html; done.hidden = false;
  const retryBtn = done.querySelector("button[data-retry]");
  if (retryBtn) {
    retryBtn.addEventListener("click", async () => {
      if (window.signinBeforeStart && !(await window.signinBeforeStart())) return;
      try {
        const probe = await fetch(base, {cache: "no-store", redirect: "manual"});
        if ([404, 410].includes(probe.status)) {
          over = false;
          finish(CONFIG.outcomes.expired);
          return;
        }
      } catch (_) {}
      over = false;
      failures = 0;
      cancellationUncertain = false;
      currentState = "ready";
      canRestart = false;
      closingActive = false;
      pendingRestart = false;
      done.hidden = true;
      $("view").hidden = false;
      begin(true);
    });
  }
  if (CONFIG.returnUrl) {
    const back = document.createElement("a"); back.href = CONFIG.returnUrl;
    back.textContent = "Back to Connections"; back.className = "button"; done.appendChild(back);
  }
  updateChrome();
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
  if (pendingRestart && (s.state === "cancelled" || s.state === "ready")) {
    pendingRestart = false;
    closingActive = false;
    failures = 0;
    cancellationUncertain = false;
    begin(true);
    return true;
  }
  currentState = s.state;
  activeLayout = (s.layout === "phone" || s.layout === "desktop") ? s.layout : "";
  if (typeof s.can_restart === "boolean") canRestart = s.can_restart;
  else if (s.state === "waiting") canRestart = true;
  closingActive = Boolean(s.closing) && ["starting", "waiting"].includes(s.state);
  if (closingActive || s.state === "saving") cancelGen += 1;
  $("status").classList.remove("warn");
  if (!cancellationUncertain) $("recovery").hidden = true;
  const ended = outcome(s);
  if (ended !== null) {
    pendingRestart = false;
    finish(ended);
    return true;
  }
  if (s.state === "saving" || (s.state === "waiting" && !closingActive)) pendingRestart = false;
  if (s.state !== 'ready' && s.state !== 'new') {
    $("intro").hidden = true;
    document.querySelector("header .bar").hidden = false;
  }
  if (s.host) $("host").textContent = (secure && secure.test(s.host) ? "🔒 " : "") + s.host;
  $("status").textContent = closingActive
    ? (pendingRestart ? "Restarting sign-in…" : "Closing previous sign-in…")
    : (CONFIG.text[s.state] || "");
  if (s.state === "saving" || closingActive) {
    $("view").replaceChildren(); viewer = false;
    document.body.classList.remove('viewer-active');
    if (s.state === "saving") {
      const savingMsg = document.createElement("div");
      savingMsg.className = "msg";
      savingMsg.textContent = CONFIG.text.saving;
      $("view").appendChild(savingMsg);
    }
  }
  if (s.state === "waiting" && !closingActive && !viewer) {
    viewer = true;
    document.body.classList.add('viewer-active');
    $("signin-help").open = false;
    const frame = document.createElement("iframe");
    const q = new URLSearchParams({autoconnect: 1, resize: "scale", reconnect: 1, reconnect_delay: 1500,
                                   path: "../vnc", quality: 8, show_dot: 0});  // relative to the viewer's own address
    frame.src = `${base}/novnc/vnc.html?${q}`;
    frame.title = CONFIG.frameTitle;
    frame.allow = "clipboard-read";
    $("view").replaceChildren(frame);
  }
  updateChrome();
  return false;
}
async function poll() {
  clearTimeout(pollTimer);
  if (over || restarting) return;
  const gen = opGen, cGen = cancelGen;
  try {
    const state = await request('state');
    if (gen !== opGen || over || restarting) return;
    // Ignore stale pre-cancel/pre-saving active polls; never block saving or terminal outcomes.
    if (cGen !== cancelGen && ["starting", "waiting"].includes(state.state) && !state.closing) {
      pollTimer = setTimeout(poll, 500);
      return;
    }
    if (show(state)) return;
    failures = 0;
  } catch (error) {
    if (gen !== opGen || over || restarting) return;
    if (recover(error)) return;
    failures += 1;
    $("status").classList.add("warn");
    $("status").textContent = 'We could not check your progress. Trying again…';
    if (failures >= 3) {
      pause('We cannot check your progress right now. Your sign-in may still be running.');
      return;
    }
  }
  const baseDelay = (currentState === "starting" || closingActive) && failures === 0 ? 500 : 1500;
  pollTimer = setTimeout(poll, Math.min(baseDelay * 2 ** failures, 6000));
}
async function begin(skipBeforeStart = false) {
  if (!skipBeforeStart && window.signinBeforeStart && !(await window.signinBeforeStart())) return;
  const gen = ++opGen;
  clearTimeout(pollTimer);
  currentState = "starting";
  activeLayout = desiredLayout();
  canRestart = false;
  closingActive = false;
  pendingRestart = false;
  $("intro").hidden = true;
  document.querySelector("header .bar").hidden = false;
  $("status").textContent = CONFIG.text.starting;
  updateChrome();
  const layout = desiredLayout();
  try {
    const started = await post("start", {layout});
    if (gen !== opGen || over) return;
    if (show(started)) return;
  } catch (error) {
    if (gen !== opGen || over) return;
    if (recover(error)) return;
  }
  if (gen === opGen && !over) poll();
}
async function restartAttempt() {
  if (over || busyAction || currentState === "saving" || !canRestart) return;
  busyAction = true;
  setActionDisabled(true);
  let gen = opGen;
  try {
    if (window.signinBeforeStart && !(await window.signinBeforeStart())) return;
    if (over || currentState === "saving" || !canRestart) return;
    restarting = true;
    pendingRestart = true;
    gen = ++opGen;
    cancelGen += 1;
    clearTimeout(pollTimer);
    $("view").replaceChildren(); viewer = false;
    document.body.classList.remove('viewer-active');
    $("layout-mismatch").hidden = true;
    $("status").textContent = CONFIG.text.starting;
    const cancelled = await request('cancel', {
      method: 'POST', headers: {"content-type": "application/json"}, body: JSON.stringify({for_restart: true}),
    }, true);
    if (gen !== opGen || over) return;
    let state = cancelled || await request('state');
    if (gen !== opGen || over) return;
    // Wait with the viewer detached while deferred cancellation settles on the login service.
    if (["starting", "waiting"].includes(state.state) && state.closing) {
      closingActive = true;
      for (let step = 0; step < 15 && ["starting", "waiting"].includes(state.state) && state.closing; step++) {
        await new Promise(resolve => setTimeout(resolve, 1000));
        if (gen !== opGen || over) return;
        state = await request('state');
        if (gen !== opGen || over) return;
      }
      if (["starting", "waiting"].includes(state.state) && state.closing) {
        restarting = false;
        busyAction = false;
        pause('We could not finish restarting the previous sign-in yet. Check its status before trying again.', true);
        return;
      }
    }
    if (state.state !== "cancelled" && state.state !== "ready") {
      pendingRestart = false;
      restarting = false;
      busyAction = false;
      if (!show(state)) poll();
      return;
    }
    failures = 0;
    cancellationUncertain = false;
    pendingRestart = false;
    restarting = false;
    busyAction = false;
    await begin(true);
  } catch (error) {
    restarting = false;
    busyAction = false;
    if (gen === opGen && !over && !recover(error))
      pause('We could not restart the sign-in. Check its status before trying again.', true);
  } finally {
    restarting = false;
    busyAction = false;
    setActionDisabled(false);
    updateChrome();
  }
}
$("go").addEventListener("click", () => begin());
$("layout-switch").addEventListener("click", () => restartAttempt());
const restart = document.createElement("button");
restart.textContent = "↻";
restart.setAttribute("aria-label", "Restart sign-in");
restart.title = "Restart sign-in";
restart.hidden = true;
const cancel = document.createElement("button");
cancel.textContent = "×";
cancel.setAttribute("aria-label", "Cancel sign-in");
cancel.title = "Cancel sign-in";
cancel.hidden = true;
const header = document.querySelector("header");
header.appendChild(restart);
header.appendChild(cancel);
restart.addEventListener("click", () => restartAttempt());
cancel.addEventListener("click", async () => {
  if (over || busyAction) return;
  busyAction = true;
  pendingRestart = false;
  const cGen = ++cancelGen;
  const gen = opGen;
  setActionDisabled(true);
  try {
    const result = await request('cancel', {method: 'POST'}, true);
    if (gen !== opGen || over) return;
    if (result && show(result)) return;
    const state = await request('state');
    if (gen !== opGen || over) return;
    if (cGen !== cancelGen && ["starting", "waiting"].includes(state.state) && !state.closing) {
      busyAction = false;
      poll();
      return;
    }
    busyAction = false;
    if (!show(state)) poll();
  } catch (error) {
    busyAction = false;
    if (gen === opGen && !over && !recover(error))
      pause('We could not confirm the cancellation. Check the sign-in status before trying again.', true);
  } finally {
    busyAction = false;
    setActionDisabled(false);
    updateChrome();
  }
});
addEventListener("resize", updateChrome);
if (CONFIG.reconnect) {
  (async () => {
    const s = await request('state');
    const retryable = (
      Object.hasOwn(CONFIG.outcomes, s.state) && !CONFIG.noRetry.includes(s.state) && s.state !== "unavailable"
    );
    if (s.state !== "ready" && !retryable) {
      $("intro").hidden = true;
      document.querySelector("header .bar").hidden = false;
      if (!show(s)) poll();
    } else if (CONFIG.autoStart) begin();
  })().catch(error => {
    if (!recover(error)) pause('We could not load your sign-in status. Check its status before starting again.');
  });
} else {
  addEventListener("pagehide", () => { if (!over && navigator.sendBeacon) navigator.sendBeacon(`${base}/cancel`); });
  if (CONFIG.autoStart) begin();
}
</script>"""
