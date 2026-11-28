"""Small, server-rendered connection screens; applications retain all account and action authority.

``body`` is trusted application markup, just like PageText's HTML fields. Escape request and account values
before including them. The optional script only refreshes the current screen and copies a code on explicit
request. It never submits a form or starts a sign-in.
"""

from __future__ import annotations

import base64
import hashlib
import html
import ipaddress
import json
import logging
import os
import re
import stat
import threading
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

import idna

from ._identity import footer as identity_footer
from .connection_state import ConnectionStatus

_DNS_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_HEX_NUMBER_LABEL = re.compile(r"^0[xX][0-9A-Fa-f]*$")

_SCRIPT = """(() => {
  const switcher = document.querySelector('details.suite-switch');
  if (switcher) {
    document.addEventListener('click', event => {
      if (switcher.open && !switcher.contains(event.target)) switcher.open = false;
    });
    document.addEventListener('keydown', event => {
      if (event.key !== 'Escape' || !switcher.open) return;
      switcher.open = false;
      switcher.querySelector('summary').focus();
    });
  }
  const content = document.getElementById('connection-content');
  if (!content) return;
  const notice = document.getElementById('connection-notice');
  const identity = doc => {
    const footer = doc.getElementById('connection-identity');
    return footer ? JSON.stringify([
      footer.dataset.service, footer.dataset.version, footer.dataset.sourceRevision
    ]) : null;
  };
  const initialIdentity = identity(document);
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
  function recover(message, label = 'Refresh status') {
    notice.replaceChildren(document.createTextNode(message + ' '));
    const link = document.createElement('a');
    link.href = location.href;
    link.textContent = label;
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
  let pollTimer = null;
  function schedulePoll(delay) {
    clearTimeout(pollTimer);
    if (!content.hasAttribute('data-refresh') || document.hidden) return;
    pollTimer = setTimeout(poll, delay);
  }
  document.addEventListener('visibilitychange', () => {
    if (!document.hidden && content.hasAttribute('data-refresh') && !polling) schedulePoll(500);
  });
  async function poll() {
    if (!content.hasAttribute('data-refresh') || polling || document.hidden) return;
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
      if (identity(doc) !== initialIdentity) {
        content.removeAttribute('data-refresh');
        recover('A new version is available. Reload to use it; your current form has been kept.', 'Reload page');
        return;
      }
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
    if (content.hasAttribute('data-refresh')) schedulePoll(Math.min(2000 * 2 ** failures, 8000));
  }
  document.addEventListener('click', async event => {
    const button = event.target.closest('button[data-copy-code]');
    if (!button) return;
    const code = document.getElementById(button.dataset.copyCode);
    if (!code) return;
    try {
      await navigator.clipboard.writeText(code.textContent);
      button.textContent = button.dataset.copied || 'Code copied';
    }
    catch (_) {
      const range = document.createRange(); range.selectNodeContents(code);
      getSelection().removeAllRanges(); getSelection().addRange(range);
      button.textContent = 'Code selected — copy it manually';
    }
  });
  if (content.hasAttribute('data-refresh')) schedulePoll(2000);
})();"""

# An exact hash allows only this fixed script, without allowing arbitrary inline scripts or new routes.
SCRIPT_SOURCE = "'sha256-" + base64.b64encode(hashlib.sha256(_SCRIPT.encode()).digest()).decode() + "'"

_STYLE = """
:root{color-scheme:light dark;font:16px/1.6 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
--bg:#f6f5f2;--surface:#fff;--surface-2:#fbfaf8;--text:#17191d;--muted:#5d636d;--faint:#656b75;
--line:#e6e4df;--line-strong:#d3d0c9;--hover:rgba(23,25,29,.045);
--accent:#1f5fbf;--accent-hover:#184f9f;--accent-soft:#e8f0fc;--on-accent:#fff;
--primary:#17191d;--on-primary:#f6f5f2;--danger:#b3261e;--status-bg:#e8f0fc;--focus:#1f5fbf;
--ok:#0a6b1f;--ok-bg:#e6f5ea;--ok-border:#b5dfc0;--warn:#8a5a00;--warn-bg:#fdf3d9;--warn-border:#f0d48a;
--bad:#b3261e;--bad-bg:#fcebe9;--bad-border:#f1bcb7;--info:#1f5fbf;--info-bg:#e8f0fc;--info-border:#bcd3f5;
--neutral-bg:#f1efeb;--neutral-border:#d3d0c9;--radius:14px;--radius-sm:8px;
--shadow:0 1px 2px rgba(23,25,29,.04),0 8px 24px -12px rgba(23,25,29,.12);
--shadow-pop:0 2px 6px rgba(23,25,29,.06),0 24px 48px -16px rgba(23,25,29,.28);
color:var(--text);background:var(--bg);-webkit-text-size-adjust:100%}
*{box-sizing:border-box}body{margin:0;-webkit-font-smoothing:antialiased}
main{max-width:46rem;margin:2.25rem auto 3rem;padding:0 1.25rem;overflow-wrap:anywhere}
h1{font-size:clamp(1.6rem,5vw,1.95rem);font-weight:650;line-height:1.2;letter-spacing:-.025em;margin:0 0 .6rem}
h2{font-size:1.1rem;font-weight:650;line-height:1.4;letter-spacing:-.01em;margin:0 0 .7rem}
h3{font-size:1rem;font-weight:650}p{margin:.7rem 0;overflow-wrap:anywhere}
.eyebrow{font-size:.75rem;font-weight:650;letter-spacing:.08em;text-transform:uppercase;
color:var(--faint);margin:0 0 .5rem}
.intro,.muted,.help{color:var(--muted)}.intro{margin-bottom:1.5rem;max-width:70ch}
article,.panel{background:var(--surface);padding:1.4rem 1.5rem;border:1px solid var(--line);
border-radius:var(--radius);box-shadow:var(--shadow);margin:1rem 0}
article>:first-child,.panel>:first-child{margin-top:0}article>:last-child,.panel>:last-child{margin-bottom:0}
[role=status]{padding:.5rem .8rem;background:var(--status-bg);border-radius:var(--radius-sm);font-weight:600}
a{color:var(--accent);text-underline-offset:.2em}a:hover{color:var(--accent-hover)}
button,.button{font:inherit;font-weight:550;min-height:2.8rem;padding:.6rem 1.05rem;
border:1px solid var(--primary);border-radius:10px;background:var(--primary);color:var(--on-primary);
display:inline-block;text-decoration:none;cursor:pointer;line-height:1.4;max-width:100%;white-space:normal;
overflow-wrap:anywhere;transition:opacity .15s,border-color .15s,background-color .15s}
button:hover,.button:hover{opacity:.88;color:var(--on-primary)}
button.secondary,.button.secondary{color:var(--text);background:var(--surface);border-color:var(--line-strong)}
button.secondary:hover,.button.secondary:hover{opacity:1;border-color:var(--faint);color:var(--text)}
button.danger{background:var(--danger);border-color:var(--danger);color:#fff}
button.quiet{background:transparent;color:var(--muted);border-color:transparent}
button.quiet:hover{opacity:1;background:var(--hover);color:var(--text)}
button:disabled{opacity:.55;cursor:wait}form{display:inline-block;margin:.4rem .6rem .4rem 0;max-width:100%}
a:focus-visible,button:focus-visible,summary:focus-visible,input:focus-visible,select:focus-visible,
textarea:focus-visible{outline:3px solid var(--focus);outline-offset:2px}
summary{cursor:pointer;min-height:44px;padding:.65rem 0;font-weight:600;color:var(--muted)}
details{border-top:1px solid var(--line);margin-top:1rem;padding-top:.3rem}details p{color:var(--muted)}
details.manage summary{color:var(--danger)}label{display:block;min-height:2.8rem;padding:.4rem 0}
input,select,textarea{font:inherit;color:inherit;max-width:100%;accent-color:var(--accent)}
input[type=text],input[type=search],input[type=email],input[type=number],input[type=password],select,textarea{
min-height:44px;padding:.5rem .7rem;border:1px solid var(--line-strong);border-radius:var(--radius-sm);
background:var(--surface)}
input[type=checkbox]{margin-right:.5rem}
code{overflow-wrap:anywhere;font:.95em ui-monospace,SFMono-Regular,Menlo,monospace}time{white-space:normal}
ol{padding-left:1.5rem}li{margin:.6rem 0}ul{padding-left:1.2rem}
.code{font:700 1.6rem/1.5 ui-monospace,SFMono-Regular,Menlo,monospace;letter-spacing:.04em;user-select:all}
#connection-content:focus{outline:0}
#connection-notice{border:1px solid var(--line);padding:1rem;border-radius:var(--radius-sm);
background:var(--surface);box-shadow:var(--shadow)}
#connection-identity{font-size:.8rem;color:var(--faint);margin-top:1.75rem;user-select:text}
#connection-identity details{border:0;margin:0;padding:0}
#connection-identity summary{font-size:inherit;font-weight:400;min-height:24px;padding:.2rem 0;color:inherit}
#connection-identity small{font-size:inherit}
#connection-identity p{margin:.25rem 0 0}
#connection-identity code{display:block;white-space:normal;overflow-wrap:anywhere;user-select:all}
.suite-bar{position:sticky;top:0;z-index:20;border-bottom:1px solid var(--line);
background:color-mix(in srgb,var(--bg) 86%,transparent);backdrop-filter:saturate(1.4) blur(14px);
-webkit-backdrop-filter:saturate(1.4) blur(14px)}
.suite-inner{display:flex;align-items:center;gap:.75rem;min-height:60px;max-width:76rem;margin:0 auto;
padding:.5rem 1.25rem}
.suite-brand{display:flex;align-items:center;gap:.65rem;min-width:0;margin-right:auto;color:var(--text);
text-decoration:none;border-radius:10px}
a.suite-brand:hover{color:var(--text)}
.suite-title{display:grid;min-width:0;line-height:1.2}
.suite-title b{font-weight:650;letter-spacing:-.01em;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.suite-title small{font-size:.75rem;color:var(--faint)}
.suite-mark{flex:none;display:grid;place-content:center;width:32px;height:32px;border-radius:9px;color:#fff;
font-weight:700;font-size:.95rem;letter-spacing:-.02em;text-transform:uppercase;--h:222;
background:linear-gradient(135deg,hsl(var(--h) 62% 22%),hsl(var(--h) 76% 54%));
box-shadow:0 4px 12px -4px hsl(var(--h) 76% 54%/.6)}
.suite-mark.sm{width:28px;height:28px;border-radius:8px;font-size:.85rem}
.suite-mark.h1{--h:262}.suite-mark.h2{--h:292}.suite-mark.h3{--h:334}.suite-mark.h4{--h:8}
.suite-mark.h5{--h:28}.suite-mark.h6{--h:146}.suite-mark.h7{--h:172}.suite-mark.h8{--h:196}
.suite-user{display:flex;align-items:center;gap:.45rem;min-width:0;font-size:.875rem;color:var(--muted)}
.suite-user span{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:14rem}
.suite-user i{flex:none;display:grid;place-content:center;width:28px;height:28px;border-radius:50%;
background:var(--neutral-bg);border:1px solid var(--line);color:var(--text);font-style:normal;font-weight:650;
font-size:.75rem;text-transform:uppercase}
details.suite-switch{position:relative;border:0;margin:0;padding:0}
.suite-switch>summary{display:flex;align-items:center;gap:.5rem;min-height:40px;padding:0 .8rem;
border:1px solid var(--line-strong);border-radius:10px;background:var(--surface);color:var(--text);
font-size:.9rem;font-weight:550;list-style:none;user-select:none}
.suite-switch>summary::-webkit-details-marker{display:none}
.suite-switch>summary:hover{border-color:var(--faint)}
.suite-switch[open]>summary{background:var(--neutral-bg)}
.suite-switch svg{width:16px;height:16px;flex:none}
.suite-menu{position:absolute;right:0;top:calc(100% + .5rem);z-index:30;width:min(40rem,calc(100vw - 1.5rem));
max-height:min(34rem,calc(100vh - 5.5rem));overflow:auto;padding:.9rem;background:var(--surface);
border:1px solid var(--line);border-radius:var(--radius);box-shadow:var(--shadow-pop);
animation:suite-pop .16s cubic-bezier(.2,.7,.2,1)}
@keyframes suite-pop{from{opacity:0;transform:translateY(-6px) scale(.985)}to{opacity:1;transform:none}}
.suite-menu h2{font-size:.72rem;font-weight:650;letter-spacing:.08em;text-transform:uppercase;
color:var(--faint);margin:.5rem .6rem .35rem}
.suite-menu h2:first-child{margin-top:.1rem}
.suite-menu ul{display:grid;grid-template-columns:repeat(auto-fill,minmax(13.5rem,1fr));gap:2px;
list-style:none;margin:0 0 .4rem;padding:0}
.suite-menu li{margin:0;min-width:0}
.suite-menu a{display:flex;align-items:center;gap:.7rem;min-height:52px;padding:.5rem .6rem;border-radius:10px;
color:var(--text);text-decoration:none}
.suite-menu a:hover{background:var(--hover);color:var(--text)}
.suite-menu a[aria-current=page]{background:var(--accent-soft)}
.suite-menu a span{display:grid;min-width:0;line-height:1.25}
.suite-menu a b{font-weight:600;font-size:.92rem}
.suite-menu a small{font-size:.78rem;color:var(--muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.badge{display:inline-flex;align-items:center;gap:.4rem;padding:.15rem .6rem;border-radius:99px;
font-size:.8rem;font-weight:600;line-height:1.5;white-space:nowrap;vertical-align:middle;
color:var(--muted);background:var(--neutral-bg);border:1px solid var(--neutral-border)}
.badge::before{content:"";width:.45rem;height:.45rem;border-radius:50%;background:currentColor}
.badge.ok{color:var(--ok);background:var(--ok-bg);border-color:var(--ok-border)}
.badge.warn{color:var(--warn);background:var(--warn-bg);border-color:var(--warn-border)}
.badge.bad{color:var(--bad);background:var(--bad-bg);border-color:var(--bad-border)}
.badge.info{color:var(--info);background:var(--info-bg);border-color:var(--info-border)}
.card-head{display:flex;align-items:center;justify-content:space-between;gap:.5rem 1rem;flex-wrap:wrap;
margin-bottom:.6rem}.card-head>*{margin:0}
.actions{display:flex;flex-wrap:wrap;align-items:center;gap:.6rem;margin-top:1rem}.actions form{margin:0}
.callout{padding:.8rem 1rem;border-radius:var(--radius-sm);border:1px solid var(--neutral-border);
background:var(--neutral-bg);margin:.9rem 0}.callout>:first-child{margin-top:0}.callout>:last-child{margin-bottom:0}
.callout.ok{background:var(--ok-bg);border-color:var(--ok-border)}
.callout.warn{background:var(--warn-bg);border-color:var(--warn-border)}
.callout.bad{background:var(--bad-bg);border-color:var(--bad-border)}
.callout.info{background:var(--info-bg);border-color:var(--info-border)}
dl.facts{display:grid;grid-template-columns:minmax(7rem,max-content) 1fr;gap:.35rem 1.25rem;margin:.8rem 0}
dl.facts dt{color:var(--muted)}dl.facts dd{margin:0;font-weight:550;min-width:0}
.rows{list-style:none;margin:.6rem 0 0;padding:0}
.rows>li{display:flex;align-items:center;gap:.6rem 1rem;flex-wrap:wrap;margin:0;padding:.8rem 0;
border-top:1px solid var(--line)}.rows>li:first-child{border-top:0}
.rows .who{display:flex;align-items:center;gap:.7rem;flex:1 1 14rem;min-width:0}
.rows .who>span{display:grid;min-width:0;line-height:1.3}.rows .who small{color:var(--muted);font-size:.85rem}
.rows form{margin:0}
.avatar{flex:none;display:grid;place-content:center;width:36px;height:36px;border-radius:50%;
background:var(--neutral-bg);border:1px solid var(--line);font-weight:650;font-size:.9rem;text-transform:uppercase}
.hero{position:relative;overflow:hidden;border:0;color:#fff;
background:radial-gradient(120% 140% at 0% 0%,#1c3f9c 0%,#14245a 45%,#0c1535 100%);
box-shadow:0 1px 2px rgba(12,21,53,.2),0 18px 40px -18px rgba(20,36,90,.7);
--muted:rgba(255,255,255,.76);--text:#fff;--line:rgba(255,255,255,.18);--line-strong:rgba(255,255,255,.3);
--primary:#fff;--on-primary:#14245a;--surface:rgba(255,255,255,.1);--accent:#bcd6ff;--accent-hover:#fff;
--status-bg:rgba(255,255,255,.12);--hover:rgba(255,255,255,.12);--focus:#fff}
.hero::after{content:"";position:absolute;right:-80px;top:-120px;width:320px;height:320px;border-radius:50%;
background:radial-gradient(circle,rgba(106,168,245,.35),transparent 65%);pointer-events:none}
.hero>*{position:relative;z-index:1}
.hero .badge{color:#fff;background:rgba(255,255,255,.14);border-color:rgba(255,255,255,.24)}
.hero .badge.ok::before{background:#7fe19a}.hero .badge.warn::before{background:#ffd166}
.hero .badge.bad::before{background:#ffaaa2}
ol.steps{list-style:none;counter-reset:step;padding:0;margin:1rem 0}
ol.steps>li{counter-increment:step;position:relative;padding-left:2.6rem;margin:.9rem 0;min-height:1.8rem}
ol.steps>li::before{content:counter(step);position:absolute;left:0;top:-.05rem;display:grid;place-content:center;
width:1.8rem;height:1.8rem;border-radius:50%;background:var(--accent-soft);color:var(--accent);
font-weight:650;font-size:.85rem}
.grid-2{display:grid;grid-template-columns:repeat(auto-fit,minmax(16rem,1fr));gap:1rem}
.grid-2>article,.grid-2>.panel{margin:0}
main>*,#connection-content>*{animation:rise .4s cubic-bezier(.2,.7,.2,1) both}
@keyframes rise{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}
details.endpoint{margin-top:1.5rem;padding-top:.2rem}
details.endpoint .address{display:flex;flex-wrap:wrap;align-items:center;gap:.6rem;padding:.6rem .6rem .6rem .9rem;
border:1px solid var(--line-strong);border-radius:10px;background:var(--surface)}
details.endpoint .address code{flex:1 1 14rem;min-width:0;user-select:all}
[hidden]{display:none!important}
@media(prefers-color-scheme:dark){:root{--bg:#0d0e10;--surface:#17181b;--surface-2:#1c1e22;--text:#eef0f2;
--muted:#a2a8b1;--faint:#8a919b;--line:#26282d;--line-strong:#35383e;--hover:rgba(255,255,255,.06);
--accent:#6aa8f5;--accent-hover:#8fbdf8;--accent-soft:#1a2a40;--on-accent:#0d1b2e;
--primary:#eef0f2;--on-primary:#0d0e10;--danger:#c9453d;--status-bg:#1a2a40;--focus:#6aa8f5;
--ok:#53c556;--ok-bg:#12261a;--ok-border:#1f4a2c;--warn:#f0b849;--warn-bg:#2a2210;--warn-border:#57451a;
--bad:#f2867f;--bad-bg:#2c1614;--bad-border:#5a2a26;--info:#6aa8f5;--info-bg:#1a2a40;--info-border:#2b456b;
--neutral-bg:#1f2126;--neutral-border:#35383e;
--shadow:0 1px 2px rgba(0,0,0,.3),0 10px 30px -14px rgba(0,0,0,.6);
--shadow-pop:0 2px 6px rgba(0,0,0,.4),0 24px 48px -16px rgba(0,0,0,.8)}
details.manage summary{color:#f2867f}}
@media(max-width:560px){main{margin:1.25rem auto 2rem;padding:0 1rem}article,.panel{padding:1.1rem}
form{display:block;margin:.6rem 0}button,.button{width:100%;text-align:center}
.suite-inner{padding:.4rem 1rem;gap:.5rem}
.suite-user span,.suite-switch>summary span{position:absolute;width:1px;height:1px;overflow:hidden;
clip-path:inset(50%);white-space:nowrap}
details.suite-switch{position:static}.suite-menu{left:.75rem;right:.75rem;top:calc(100% + .4rem);width:auto}
.suite-menu ul{grid-template-columns:1fr}
.actions{display:grid}dl.facts{grid-template-columns:1fr;gap:0}dl.facts dd{margin-bottom:.5rem}}
@media(prefers-reduced-motion:reduce){*{scroll-behavior:auto!important;animation:none!important;
transition:none!important}}
"""


_GRID_ICON = (
    '<svg viewBox="0 0 16 16" fill="currentColor" aria-hidden="true">'
    '<rect x="1" y="1" width="4" height="4" rx="1.2"/><rect x="6" y="1" width="4" height="4" rx="1.2"/>'
    '<rect x="11" y="1" width="4" height="4" rx="1.2"/><rect x="1" y="6" width="4" height="4" rx="1.2"/>'
    '<rect x="6" y="6" width="4" height="4" rx="1.2"/><rect x="11" y="6" width="4" height="4" rx="1.2"/>'
    '<rect x="1" y="11" width="4" height="4" rx="1.2"/><rect x="6" y="11" width="4" height="4" rx="1.2"/>'
    '<rect x="11" y="11" width="4" height="4" rx="1.2"/></svg>'
)
_MARK_HUES = 9


@dataclass(frozen=True)
class SuiteLink:
    """One sibling application the signed-in person may open."""

    label: str
    url: str
    section: str = ""
    description: str = ""
    current: bool = False

    def __post_init__(self) -> None:
        _https_url(self.url)


@dataclass(frozen=True)
class SuiteEndpoint:
    """One address visitors copy into another program, such as an assistant, with a short explanation."""

    title: str
    url: str
    help: str = ""

    def __post_init__(self) -> None:
        _https_url(self.url)


@dataclass(frozen=True)
class Suite:
    """Navigation between sibling applications. Showing a link grants nothing.

    Each destination still authenticates and authorizes its own visitors; a
    hidden link is a convenience, never an access control.
    """

    name: str
    links: tuple[SuiteLink, ...] = ()
    account: str = ""
    endpoint: SuiteEndpoint | None = None


def _https_url(value: object) -> str:
    error = "suite links must be clean https:// URLs"
    if (
        not isinstance(value, str)
        or not value.startswith("https://")
        or "#" in value
        or any(c.isspace() or ord(c) <= 32 or ord(c) == 127 or c == "\\" for c in value)
    ):
        raise ValueError(error)
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        raise ValueError(error) from None
    host = parsed.hostname
    bracketed = parsed.netloc.startswith("[")
    expected = (f"[{host}]" if bracketed else (host or "")) + (f":{port}" if port is not None else "")
    if (
        not host
        or parsed.username is not None
        or parsed.password is not None
        or parsed.netloc.lower() != expected
        or not _valid_hostname(host, bracketed=bracketed)
    ):
        raise ValueError(error)
    return value


def _origin(value: str) -> str:
    try:
        parsed = urlsplit(value)
        return f"{parsed.scheme}://{parsed.netloc}".lower() if parsed.scheme and parsed.netloc else ""
    except ValueError:
        return ""


@dataclass(frozen=True)
class _DirectoryEntry:
    label: str
    url: str
    section: str
    description: str
    groups: frozenset[str]
    endpoint: bool = False


@dataclass(frozen=True)
class SuiteDirectory:
    """A deployment's validated list of sibling applications, filtered per visitor."""

    name: str
    entries: tuple[_DirectoryEntry, ...]
    endpoint: SuiteEndpoint | None = None

    @classmethod
    def from_json(cls, text: str) -> SuiteDirectory:
        """Parse ``{"name": ..., "apps": [{"label", "url", "section"?, "description"?, "groups"?, "endpoint"?}]}``.

        An optional top-level ``"endpoint": {"title", "url", "help"?}`` is one address
        to copy into another program; it appears only on applications whose entry sets
        ``"endpoint": true``.

        ``groups`` lists identity-provider groups, any one of which shows the
        link; an absent or empty list shows it to every signed-in visitor.
        """
        try:
            data = json.loads(text)
        except (TypeError, ValueError):
            raise ValueError("suite directory must be a JSON object") from None
        if (
            not isinstance(data, dict)
            or set(data) - {"name", "apps", "endpoint"}
            or not isinstance(data.get("apps"), list)
        ):
            raise ValueError("suite directory must be a JSON object with name and apps")
        name = data.get("name", "")
        if not isinstance(name, str) or not name.strip() or len(name) > 40:
            raise ValueError("suite directory needs a short name")
        entries = []
        for item in data["apps"]:
            if not isinstance(item, dict) or set(item) - {
                "label",
                "url",
                "section",
                "description",
                "groups",
                "endpoint",
            }:
                raise ValueError("invalid suite directory entry")
            label = item.get("label")
            section = item.get("section", "")
            description = item.get("description", "")
            groups = item.get("groups", [])
            if (
                not isinstance(label, str)
                or not label.strip()
                or len(label) > 40
                or not isinstance(section, str)
                or len(section) > 40
                or not isinstance(description, str)
                or len(description) > 80
                or not isinstance(groups, list)
                or not all(isinstance(group, str) and group for group in groups)
                or not isinstance(item.get("endpoint", False), bool)
            ):
                raise ValueError("invalid suite directory entry")
            entries.append(
                _DirectoryEntry(
                    label.strip(),
                    _https_url(item.get("url")),
                    section.strip(),
                    description.strip(),
                    frozenset(groups),
                    item.get("endpoint", False),
                )
            )
        if len(entries) > 60 or len({entry.url for entry in entries}) != len(entries):
            raise ValueError("suite directory entries must be unique and at most 60")
        endpoint = data.get("endpoint")
        if endpoint is not None:
            if (
                not isinstance(endpoint, dict)
                or set(endpoint) - {"title", "url", "help"}
                or not isinstance(endpoint.get("title"), str)
                or not endpoint["title"].strip()
                or len(endpoint["title"]) > 60
                or not isinstance(endpoint.get("help", ""), str)
                or len(endpoint.get("help", "")) > 240
            ):
                raise ValueError("invalid suite directory endpoint")
            endpoint = SuiteEndpoint(endpoint["title"].strip(), endpoint.get("url"), endpoint.get("help", "").strip())
        elif any(entry.endpoint for entry in entries):
            raise ValueError("an application shows the endpoint but the directory defines none")
        return cls(name.strip(), tuple(entries), endpoint)

    def suite(self, *, groups: Iterable[str], current: str = "", account: str = "") -> Suite:
        """Links for a visitor in ``groups``; ``current`` is this application's URL or origin."""
        held = frozenset(groups)
        here = _origin(current)
        links = []
        shown = None
        for entry in self.entries:
            is_current = bool(here) and _origin(entry.url) == here
            if is_current and entry.endpoint:
                shown = self.endpoint
            if is_current or not entry.groups or entry.groups & held:
                links.append(SuiteLink(entry.label, entry.url, entry.section, entry.description, is_current))
        return Suite(self.name, tuple(links), account, shown)


SUITE_VARIABLE = "SIGNIN_WINDOW_SUITE"
SUITE_FILE_VARIABLE = "SIGNIN_WINDOW_SUITE_FILE"
_MAX_SUITE_BYTES = 65536


class SuiteSource:
    """Live or static source for a ``SuiteDirectory``.

    When backed by a file path (for example via ``SIGNIN_WINDOW_SUITE_FILE``),
    ``current()`` re-reads the file whenever ``(st_ino, st_mtime_ns, st_size)``
    changes so atomic replacements inside a mounted directory take effect on the
    next request without restarting the process. Read or validation errors log a
    warning and retain the last valid directory in memory.
    """

    def __init__(self, *, path: str | os.PathLike[str] | None = None, directory: SuiteDirectory | None = None):
        if path is not None and directory is not None:
            raise ValueError("Specify either path or directory, not both")
        self._path = Path(path) if path is not None else None
        self._directory = directory
        self._sig: tuple[int, int, int] | None = None
        self._last_error: tuple[object, ...] | None = None
        self._lock = threading.Lock()

    @classmethod
    def from_environment(cls) -> SuiteSource:
        """Load from ``SIGNIN_WINDOW_SUITE_FILE`` if set, else ``SIGNIN_WINDOW_SUITE``."""
        file_path = os.environ.get(SUITE_FILE_VARIABLE, "").strip()
        if file_path:
            source = cls(path=file_path)
            source.current()
            return source
        text = os.environ.get(SUITE_VARIABLE, "").strip()
        if not text:
            return cls(directory=None)
        try:
            return cls(directory=SuiteDirectory.from_json(text))
        except ValueError as error:
            logging.getLogger(__name__).warning("Ignoring %s: %s", SUITE_VARIABLE, error)
            return cls(directory=None)

    def _log_error(self, sig: tuple[int, int, int] | None, error: Exception) -> None:
        key = (sig, type(error).__name__, str(error))
        if key != self._last_error:
            self._last_error = key
            logging.getLogger(__name__).warning("Ignoring %s (%s): %s", SUITE_FILE_VARIABLE, self._path, error)

    def current(self) -> SuiteDirectory | None:
        if self._path is None:
            return self._directory
        with self._lock:
            sig: tuple[int, int, int] | None = None
            try:
                st = os.lstat(self._path)
                if not stat.S_ISREG(st.st_mode):
                    raise ValueError("suite file must be a regular file")
                sig = (st.st_ino, st.st_mtime_ns, st.st_size)
                if sig == self._sig:
                    return self._directory
                if st.st_size > _MAX_SUITE_BYTES:
                    raise ValueError(f"suite file exceeds {_MAX_SUITE_BYTES} bytes")
                flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                fd = os.open(self._path, flags)
                try:
                    fst = os.fstat(fd)
                    if not stat.S_ISREG(fst.st_mode):
                        raise ValueError("suite file must be a regular file")
                    if fst.st_size > _MAX_SUITE_BYTES:
                        raise ValueError(f"suite file exceeds {_MAX_SUITE_BYTES} bytes")
                    with os.fdopen(fd, "rb") as handle:
                        fd = -1
                        raw = handle.read(_MAX_SUITE_BYTES + 1)
                finally:
                    if fd >= 0:
                        os.close(fd)
                if len(raw) > _MAX_SUITE_BYTES:
                    raise ValueError(f"suite file exceeds {_MAX_SUITE_BYTES} bytes")
                parsed = SuiteDirectory.from_json(raw.decode("utf-8"))
            except (OSError, UnicodeDecodeError, ValueError) as error:
                self._log_error(sig, error)
                return self._directory
            self._directory = parsed
            self._sig = (fst.st_ino, fst.st_mtime_ns, fst.st_size)
            self._last_error = None
            return self._directory


def _mark(label: str, *, small: bool = False) -> str:
    text = label.strip() or "?"
    hue = sum(text.lower().encode()) % _MARK_HUES
    size = " sm" if small else ""
    hue_class = f" h{hue}" if hue else ""
    return f'<span class="suite-mark{hue_class}{size}" aria-hidden="true">{html.escape(text[0])}</span>'


def _endpoint(suite: Suite | None) -> str:
    if suite is None or suite.endpoint is None:
        return ""
    endpoint = suite.endpoint
    return (
        f'<details class="endpoint"><summary>{html.escape(endpoint.title)}</summary>'
        + (f"<p>{html.escape(endpoint.help)}</p>" if endpoint.help else "")
        + f'<div class="address"><code id="connection-suite-endpoint">{html.escape(_https_url(endpoint.url))}</code>'
        '<button type="button" class="secondary" data-copy-code="connection-suite-endpoint" '
        'data-copied="Address copied">Copy address</button></div>'
        "</details>"
    )


def _suite_bar(title: str, suite: Suite | None) -> str:
    """The shared top bar: this application's mark, and the switcher when siblings are configured."""
    current = next((link for link in suite.links if link.current), None) if suite else None
    label = current.label if current else title
    brand = (
        f'{_mark(label)}<span class="suite-title"><b>{html.escape(label)}</b>'
        f"<small>{html.escape(suite.name if suite else 'Connections')}</small></span>"
    )
    parts = ['<header class="suite-bar"><div class="suite-inner">']
    if current:
        parts.append(f'<a class="suite-brand" href="{html.escape(_https_url(current.url), quote=True)}">{brand}</a>')
    else:
        parts.append(f'<div class="suite-brand">{brand}</div>')
    others = [link for link in suite.links if not link.current] if suite else []
    if suite and others:
        parts.append(
            '<nav aria-label="Your apps"><details class="suite-switch">'
            f'<summary aria-label="Apps">{_GRID_ICON}<span>Apps</span></summary><div class="suite-menu">'
        )
        sections: dict[str, list[SuiteLink]] = {}
        for link in suite.links:
            sections.setdefault(link.section, []).append(link)
        for section, links in sections.items():
            if section:
                parts.append(f"<h2>{html.escape(section)}</h2>")
            parts.append("<ul>")
            for link in links:
                here = ' aria-current="page"' if link.current else ""
                description = f"<small>{html.escape(link.description)}</small>" if link.description else ""
                target = html.escape(_https_url(link.url), quote=True)
                parts.append(
                    f'<li><a href="{target}"{here}>{_mark(link.label, small=True)}'
                    f"<span><b>{html.escape(link.label)}</b>{description}</span></a></li>"
                )
            parts.append("</ul>")
        parts.append("</div></details></nav>")
    if suite and suite.account.strip():
        account = suite.account.strip()
        parts.append(
            f'<div class="suite-user"><i aria-hidden="true">{html.escape(account[0])}</i>'
            f"<span>{html.escape(account)}</span></div>"
        )
    parts.append("</div></header>")
    return "".join(parts)


@dataclass(frozen=True)
class PageIdentity:
    """Host application's build metadata, never the renderer package's version."""

    service: str
    version: str
    source_revision: str


def _valid_hostname(host: str, *, bracketed: bool) -> bool:
    if not host or len(host) > 253 or "%" in host:
        return False
    if bracketed:
        try:
            ipaddress.IPv6Address(host)
            return True
        except ValueError:
            return False
    try:
        ipaddress.IPv4Address(host)
        return True
    except ValueError:
        pass
    labels = host.split(".")
    if labels[-1].isdigit() or _HEX_NUMBER_LABEL.fullmatch(labels[-1]):
        return False
    if not all(_DNS_LABEL.fullmatch(label) for label in labels):
        return False
    for label in labels:
        if label.lower().startswith("xn--"):
            try:
                idna.decode(label, uts46=True)
            except idna.IDNAError:
                return False
    return True


def _preconnect_origin(value: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or any(char.isspace() or ord(char) < 32 or ord(char) == 127 or char == "\\" for char in value)
    ):
        raise ValueError("preconnect must be a clean https:// origin")
    parsed = urlsplit(value)
    port = parsed.port
    bracketed = parsed.netloc.startswith("[")
    host = parsed.hostname
    expected_netloc = (f"[{host}]" if bracketed else (host or "")) + (f":{port}" if port is not None else "")
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or not host
        or parsed.netloc.lower() != expected_netloc
        or not _valid_hostname(host, bracketed=bracketed)
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
        or value != f"https://{parsed.netloc}"
    ):
        raise ValueError("preconnect must be a clean https:// origin")
    return value


def page(
    title: str,
    body: str,
    *,
    intro: str = "",
    refresh: bool = False,
    login_url: str = "/connections/login",
    identity: PageIdentity | None = None,
    preconnect: str | None = None,
    suite: Suite | None = None,
) -> str:
    """Render trusted application markup, with optional host-supplied build identity.

    ``suite`` adds links to sibling applications in the top bar; see ``SuiteDirectory``.
    """
    live = " data-refresh" if refresh else ""
    footer = identity_footer(identity, element_id="connection-identity") if identity is not None else ""
    preconnect_tag = (
        f'<link rel="preconnect" href="{html.escape(_preconnect_origin(preconnect), quote=True)}" crossorigin>'
        if preconnect is not None
        else ""
    )
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        f"{preconnect_tag}"
        f"<title>{html.escape(title)} · {html.escape(suite.name if suite else 'Connections')}</title>"
        f"<style>{_STYLE}</style></head><body>{_suite_bar(title, suite)}<main>"
        + ("" if suite else '<p class="eyebrow">Connections</p>')
        + f"<h1>{html.escape(title)}</h1>"
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
        + _endpoint(suite)
        + footer
        + f"</main><script>{_SCRIPT}</script></body></html>"
    )


_TONES = ("neutral", "ok", "warn", "bad", "info")


def badge(text: str, tone: str = "neutral") -> str:
    """A compact status pill; ``tone`` is neutral, ok, warn, bad or info."""
    if tone not in _TONES:
        raise ValueError("badge tone must be neutral, ok, warn, bad or info")
    tone_class = "" if tone == "neutral" else f" {tone}"
    return f'<span class="badge{tone_class}">{html.escape(text)}</span>'


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


def _activity_url(value: str | None) -> str | None:
    if not value or any(ord(char) <= 32 or ord(char) == 127 or char == "\\" for char in value):
        return None
    try:
        parsed = urlsplit(value)
        if value.startswith("/") and not value.startswith("//") and not parsed.scheme and not parsed.netloc:
            return value
        if parsed.scheme == "https" and parsed.hostname and parsed.username is None and parsed.password is None:
            _ = parsed.port  # Validate malformed/out-of-range ports before returning a link.
            return value
    except ValueError:
        pass
    return None


def controls_panel(
    status: ConnectionStatus, *, granted_scopes: Sequence[str] | None = None, pause_form: str = ""
) -> str:
    """Opt-in shared controls; only ``pause_form`` is trusted application HTML.

    The application supplies scopes from its current grant and an authenticated,
    CSRF-protected pause/resume form. Rendering neither grants access nor starts
    work. Activity URLs allow root-relative paths or HTTPS, never executable URLs.
    """
    parts = [
        '<section class="panel" aria-label="Connection controls">',
        "<h2>Connection controls</h2>",
        '<p role="status">' + ("Paused" if status.paused else "Not paused") + "</p>",
        "<p>Pausing stops application work without disconnecting your saved connection.</p>",
        pause_form,
    ]
    if granted_scopes is not None:
        parts.append("<h3>Granted access</h3>")
        parts.append(
            "<ul>" + "".join(f"<li><code>{html.escape(scope)}</code></li>" for scope in granted_scopes) + "</ul>"
            if granted_scopes
            else "<p>No scopes granted.</p>"
        )
    parts.append("<h3>Recent activity</h3>")
    if status.activity:
        parts.append("<ol>")
        for item in status.activity:
            summary = html.escape(item.summary)
            target = _activity_url(item.url)
            if target:
                summary = f'<a href="{html.escape(target, quote=True)}">{summary}</a>'
            parts.extend(
                [
                    f"<li><p>{summary}</p><p>{html.escape(item.status)}</p>",
                    timestamp(item.occurred_at, label="Recorded"),
                    "</li>",
                ]
            )
        parts.append("</ol>")
    else:
        parts.append("<p>No activity recorded.</p>")
    parts.append("</section>")
    return "".join(parts)
