"""Small, server-rendered connection screens; applications retain all account and action authority.

``body`` is trusted application markup, just like PageText's HTML fields. Escape request and account values
before including them. The optional script only refreshes the current screen and copies a code on explicit
request. It never submits a form or starts a sign-in.
"""

from __future__ import annotations

import base64
import hashlib
import html
from datetime import UTC, datetime

_SCRIPT = """(() => {
  const content = document.getElementById('connection-content');
  if (!content) return;
  const notice = document.getElementById('connection-notice');
  let failures = 0, polling = false;
  const initialValues = new WeakMap();
  const controls = () => Array.from(content.querySelectorAll('input:not([type=hidden]),textarea,select'));
  function value(element) {
    if (element.type === 'checkbox' || element.type === 'radio') return element.checked;
    if (element.tagName === 'SELECT') return JSON.stringify(Array.from(element.options, o => o.selected));
    return element.value;
  }
  function rememberValues() { controls().forEach(element => initialValues.set(element, value(element))); }
  rememberValues();
  function recover(message) {
    notice.replaceChildren(document.createTextNode(message + ' '));
    const link = document.createElement('a');
    link.href = location.href;
    link.textContent = 'Refresh status';
    notice.append(link);
    notice.hidden = false;
  }
  const focusable = 'button,a,input,select,textarea,summary';
  function matchesKey(element, key) {
    if (key.id) return element.id === key.id;
    return element.tagName === key.tag && element.textContent === key.text &&
      element.closest('form')?.getAttribute('action') === key.action &&
      element.getAttribute('href') === key.href && element.getAttribute('name') === key.name &&
      element.getAttribute('type') === key.type;
  }
  function focusKey(element) {
    if (!element || !content.contains(element)) return null;
    const key = {tag: element.tagName, text: element.textContent,
                 action: element.closest('form')?.getAttribute('action'),
                 href: element.getAttribute('href'), id: element.id, name: element.getAttribute('name'),
                 type: element.getAttribute('type')};
    const matches = Array.from(content.querySelectorAll(focusable)).filter(item => matchesKey(item, key));
    key.position = matches.indexOf(element);
    return key;
  }
  function restoreFocus(key) {
    if (!key) return;
    const matches = Array.from(content.querySelectorAll(focusable)).filter(item => matchesKey(item, key));
    const replacement = matches[key.position];
    (replacement || content).focus({preventScroll: true});
  }
  async function poll() {
    if (!content.hasAttribute('data-refresh') || polling) return;
    if (document.hidden) { setTimeout(poll, 2000); return; }
    polling = true;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10000);
    try {
      const response = await fetch(location.href, {cache: 'no-store', redirect: 'manual', signal: controller.signal});
      if (response.type === 'opaqueredirect' || response.status === 401) {
        notice.replaceChildren(document.createTextNode('Sign in to Connections again to check your progress. '));
        const link = document.createElement('a');
        link.href = content.dataset.loginUrl;
        link.textContent = 'Sign in to Connections';
        notice.append(link); notice.hidden = false;
        return;
      }
      if (response.status === 403) {
        recover('This sign-in cannot manage this connection. Ask your administrator to check access.');
        return;
      }
      if (!response.ok || !response.headers.get('content-type')?.includes('text/html')) throw new Error('status');
      const doc = new DOMParser().parseFromString(await response.text(), 'text/html');
      const next = doc.getElementById('connection-content');
      if (!next) throw new Error('status');
      failures = 0;
      notice.hidden = true;
      // Do not interrupt an open confirmation or text selection. The server still rejects stale action forms.
      const edited = controls().some(element => value(element) !== initialValues.get(element));
      const deferred = edited || content.querySelector('details[open]') || String(getSelection());
      if (!deferred && content.innerHTML !== next.innerHTML) {
        const key = focusKey(document.activeElement);
        content.replaceChildren(...Array.from(next.childNodes));
        rememberValues();
        restoreFocus(key);
      }
      if (!deferred && !next.hasAttribute('data-refresh')) content.removeAttribute('data-refresh');
    } catch (_) {
      failures += 1;
      if (failures >= 3) { recover('We could not refresh the status. Your sign-in may still be running.'); return; }
    } finally { clearTimeout(timeout); polling = false; }
    if (content.hasAttribute('data-refresh')) setTimeout(poll, Math.min(2000 * 2 ** failures, 8000));
  }
  document.addEventListener('click', async event => {
    const button = event.target.closest('button[data-copy-code]');
    if (!button) return;
    const code = document.getElementById(button.dataset.copyCode);
    if (!code) return;
    try { await navigator.clipboard.writeText(code.textContent); button.textContent = 'Code copied'; }
    catch (_) {
      const range = document.createRange(); range.selectNodeContents(code);
      getSelection().removeAllRanges(); getSelection().addRange(range);
      button.textContent = 'Code selected — copy it manually';
    }
  });
  if (content.hasAttribute('data-refresh')) setTimeout(poll, 2000);
})();"""

# An exact hash allows only this fixed script, without allowing arbitrary inline scripts or new routes.
SCRIPT_SOURCE = "'sha256-" + base64.b64encode(hashlib.sha256(_SCRIPT.encode()).digest()).decode() + "'"

_STYLE = """
:root{color-scheme:light dark;font:16px/1.6 system-ui,-apple-system,"Segoe UI",sans-serif;
--bg:#f4f6fa;--surface:#fff;--text:#192635;--muted:#536272;--line:#d7dfe9;--accent:#2358bd;--on-accent:#fff;
--danger:#9e3036;--status-bg:#edf2fa;--focus:#a35d00;color:var(--text);background:var(--bg)}
*{box-sizing:border-box}body{margin:0}main{max-width:46rem;margin:2.5rem auto;padding:1.25rem;overflow-wrap:anywhere}
h1{font-size:clamp(1.6rem,5vw,2rem);line-height:1.25;letter-spacing:-.04em;margin:0 0 .75rem}
h2{font-size:1.2rem;line-height:1.4;margin:0 0 .8rem}h3{font-size:1rem}p{margin:.7rem 0;overflow-wrap:anywhere}
.eyebrow{font-size:.8rem;font-weight:700;letter-spacing:.08em;text-transform:uppercase;
color:var(--muted);margin:0 0 .5rem}
.intro,.muted,.help{color:var(--muted)}.intro{margin-bottom:1.5rem}
article,.panel{background:var(--surface);padding:1.5rem;border:1px solid var(--line);border-radius:1rem;margin:1rem 0}
[role=status]{padding:.45rem .75rem;background:var(--status-bg);border-radius:.5rem;font-weight:600}
a{color:var(--accent);text-underline-offset:.2em}button,.button{font:inherit;min-height:44px;padding:.65rem 1rem;
border:1px solid var(--accent);border-radius:.6rem;background:var(--accent);color:var(--on-accent);
display:inline-block;text-decoration:none;cursor:pointer;line-height:1.4}
button.secondary,.button.secondary{color:var(--accent);background:var(--surface);border-color:var(--line)}
button.danger{background:var(--danger);border-color:var(--danger);color:#fff}
button.quiet{background:transparent;color:var(--muted);border-color:transparent}
button:disabled{opacity:.65;cursor:wait}form{display:inline-block;margin:.4rem .6rem .4rem 0;max-width:100%}
a:focus-visible,button:focus-visible,summary:focus-visible,input:focus-visible{
outline:3px solid var(--focus);outline-offset:3px}
summary{cursor:pointer;min-height:44px;padding:.65rem 0;font-weight:600;color:var(--muted)}
details{border-top:1px solid var(--line);margin-top:1rem;padding-top:.3rem}details p{color:var(--muted)}
details.manage summary{color:var(--danger)}label{display:block}input{font:inherit;max-width:100%}
input[type=checkbox]{margin-right:.5rem}code{overflow-wrap:anywhere;font-size:1.1rem}time{white-space:normal}
ol{padding-left:1.5rem}li{margin:.6rem 0}ul{padding-left:1.2rem}
.code{font:700 1.6rem/1.5 ui-monospace,monospace;user-select:all}
#connection-notice{border:1px solid var(--line);padding:1rem;border-radius:.6rem;background:var(--surface)}
[hidden]{display:none!important}
@media(prefers-color-scheme:dark){:root{--bg:#121a26;--surface:#1c2736;--text:#eef2f8;--muted:#b7c4d6;
--line:#415168;--accent:#9cc0ff;--on-accent:#14263f;--danger:#be4651;--status-bg:#2a3950;--focus:#ffd486}
details.manage summary{color:#ffb4bb}}
@media(max-width:480px){main{margin:.75rem auto;padding:1rem}article,.panel{padding:1.1rem}
form{display:block;margin:.6rem 0}form button{width:100%}}
@media(prefers-reduced-motion:reduce){*{scroll-behavior:auto!important}}
"""


def page(
    title: str, body: str, *, intro: str = "", refresh: bool = False, login_url: str = "/connections/login"
) -> str:
    """Render trusted application markup inside the common accessible shell."""
    live = " data-refresh" if refresh else ""
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        f"<title>{html.escape(title)} · Connections</title><style>{_STYLE}</style></head><body><main>"
        '<p class="eyebrow">Connections</p>'
        f"<h1>{html.escape(title)}</h1>"
        + (f'<p class="intro">{html.escape(intro)}</p>' if intro else "")
        + '<p id="connection-notice" role="status" hidden></p>'
        + f'<div id="connection-content" tabindex="-1" data-login-url="{html.escape(login_url, quote=True)}"'
        f"{live}>{body}</div>"
        + (
            "<noscript><p>Status does not update automatically without JavaScript. "
            '<a href="">Refresh status</a> to check your progress.</p></noscript>'
            if refresh
            else ""
        )
        + f"</main><script>{_SCRIPT}</script></body></html>"
    )


def disconnect_confirmation(form: str, service: str, effect: str) -> str:
    """Require opening the effect explanation before the application's existing disconnect form."""
    return (
        f'<details class="manage"><summary>Disconnect {html.escape(service)}…</summary>'
        f"<p>{html.escape(effect)}</p>{form}</details>"
    )


def timestamp(value: str | float | None, *, label: str = "Last checked") -> str:
    """A readable, unambiguous UTC timestamp, never a claim about unrecorded provider freshness."""
    try:
        date = datetime.fromtimestamp(value, UTC) if isinstance(value, int | float) else datetime.fromisoformat(value)
        if date.tzinfo is None:
            date = date.replace(tzinfo=UTC)
        date = date.astimezone(UTC)
    except (TypeError, ValueError, OverflowError, OSError):
        return f'<p class="muted">{html.escape(label)}: not recorded</p>'
    shown = f"{date.day} {date:%b %Y} at {date:%H:%M} UTC"
    return f'<p class="muted">{html.escape(label)}: <time datetime="{date.isoformat()}">{shown}</time></p>'
