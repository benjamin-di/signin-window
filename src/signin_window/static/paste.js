// Paste into the sign-in window: Ctrl+V (Cmd+V on a Mac) types the clipboard's text into the remote page.
//
// Loaded beside noVNC's own vnc.html (the relay adds one <script> tag; noVNC itself is unchanged). noVNC's keyboard
// handler swallows Ctrl+V on its canvas, so no paste event would ever fire. This module sees the key first (capture
// phase) and keeps it from noVNC without preventing the browser's default, so the browser fires a `paste` event with
// the text; then it releases the modifiers noVNC already pressed on the remote side and types the text key by key,
// paced, the way noVNC's own on-screen keyboard input does. If no paste event comes, it asks
// navigator.clipboard.readText() instead. Each Ctrl+V is typed once, by whichever of the two has its text first.
// The text is never logged or stored.
import UI from "./app/ui.js";
import KeyTable from "./core/input/keysym.js";
import keysyms from "./core/input/keysymdef.js";

const MAX_CHARS = 1000;
const PACE_MS = 20;
const FALLBACK_MS = 300;
const LATE_PASTE_MS = 5000;
const SPECIAL = { "\n": KeyTable.XK_Return, "\t": KeyTable.XK_Tab };

let typing = false;
let pending = [];
let generation = 0;

function cancelTyping() {
  pending.length = 0;
  generation++;
  if (attempt) clearTimeout(attempt.timer);
  // Keep the outstanding gesture's origin until its native paste settles or a new gesture replaces it.
}

// All edits share one bounded, paced queue. Each batch belongs to the current RFB, never a replacement window.
function enqueue(keys) {
  if (!connected() || keys.length > MAX_CHARS || pending.length + keys.length > MAX_CHARS) return false;
  const rfb = UI.rfb;
  pending.push(...keys.filter(Boolean).map(keysym => ({keysym, rfb, generation})));
  if (!typing) drain();
  return true;
}

async function drain() {
  typing = true;
  try {
    releaseHeldKeys();
    while (pending.length) {
      const item = pending.shift();
      if (item.generation !== generation || UI.rfb !== item.rfb || !connected()) continue;
      item.rfb.sendKey(item.keysym, null);
      await sleep(PACE_MS);
    }
  } finally { typing = false; }
}
let attempt = null;  // the latest Ctrl+V: when it was pressed, its fallback timer, and whether its text was typed

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

function connected() {
  return UI.rfb && UI.rfb._rfbConnectionState === "connected" && !UI.rfb.viewOnly;
}

function editable(target) {
  return target instanceof HTMLElement &&
    (target.isContentEditable || ["INPUT", "TEXTAREA", "SELECT"].includes(target.tagName));
}

function releaseHeldKeys() {
  // Ctrl/Cmd (and anything else noVNC sent as pressed) goes up on the remote side first, so the text is typed as
  // plain keys. Going through noVNC's keyboard keeps its own record right: the person's later key-up is ignored.
  const keyboard = UI.rfb._keyboard;
  if (keyboard && keyboard._keyDownList) {
    if (keyboard._altGrArmed) keyboard._interruptAltGrSequence();
    for (const code of Object.keys(keyboard._keyDownList)) {
      keyboard._sendKeyEvent(keyboard._keyDownList[code], code, false);
    }
    return;
  }
  for (const [keysym, code] of [[KeyTable.XK_Control_L, "ControlLeft"], [KeyTable.XK_Control_R, "ControlRight"],
                                [KeyTable.XK_Super_L, "MetaLeft"], [KeyTable.XK_Super_R, "MetaRight"],
                                [KeyTable.XK_Shift_L, "ShiftLeft"], [KeyTable.XK_Alt_L, "AltLeft"]]) {
    UI.rfb.sendKey(keysym, code, false);
  }
}

function type(text) {
  if (!connected() || typeof text !== "string") return;
  text = text.replace(/\r\n?/g, "\n").replace(/\n+$/, "");
  const chars = Array.from(text).slice(0, MAX_CHARS);
  enqueue(chars.map(ch => {
    const cp = ch.codePointAt(0);
    return SPECIAL[ch] ?? (cp < 0x20 || cp === 0x7f ? 0 : keysyms.lookup(cp));
  }));
}

// While the text is being typed, no key reaches noVNC: a held Ctrl repeating its key-down would press Ctrl on the
// remote side again and turn the rest of the text into shortcuts. (Its key-up is ignored by noVNC: already released.)
for (const kind of ["keydown", "keyup"]) {
  document.addEventListener(kind, event => {
    if (typing && !editable(event.target)) {
      event.stopImmediatePropagation();
      event.preventDefault();
    }
  }, true);
}

document.addEventListener("keydown", event => {
  const paste = (event.ctrlKey || event.metaKey) && !event.altKey && event.code === "KeyV";
  const native = event.target.id === "signin_input";
  if (!paste || (typing && !native) || (editable(event.target) && !native) || !connected()) return;
  // Not preventDefault: the browser's paste must still happen. Only noVNC must not see this key.
  if (!native) event.stopPropagation();
  // Each Ctrl+V is an attempt of its own, so what an earlier one did never holds this one back. An earlier one whose
  // fallback is still waiting gives way to it.
  if (attempt) clearTimeout(attempt.timer);
  const current = { at: Date.now(), timer: null, typed: false, rfb: UI.rfb, generation };
  attempt = current;
  // Native paste supplies its own text; it still needs the same gesture ownership fence.
  if (native) return;
  current.timer = setTimeout(() => {
    if (!navigator.clipboard || !navigator.clipboard.readText) return;
    navigator.clipboard.readText().then(text => {
      if (attempt !== current || current.typed || !text || current.rfb !== UI.rfb ||
          current.generation !== generation || !connected()) return;  // its paste event came first after all, or there is no text
      current.typed = true;
      type(text);
    }, () => {});  // refused: nothing typed, so this Ctrl+V's paste event may still type its text
  }, FALLBACK_MS);
}, true);

document.addEventListener("paste", event => {
  const native = event.target.id === "signin_input";
  if (editable(event.target) && !native) return;
  // The paste event of the latest Ctrl+V settles that attempt. One with no Ctrl+V before it, such as the browser's
  // own Paste menu, is typed as it is.
  const current = attempt;
  if (current) {
    clearTimeout(current.timer);
    attempt = null;
    if (current.rfb !== UI.rfb || current.generation !== generation || !connected()) {
      event.preventDefault();
      const feedback = document.getElementById("signin_feedback");
      if (feedback) feedback.textContent = "Paste was cancelled. Paste again in the current remote window.";
      return;
    }
    if (current.typed && Date.now() - current.at < LATE_PASTE_MS) {
      event.preventDefault();
      return;
    }
    current.typed = true;
  }
  if (native || !connected()) return;
  event.preventDefault();
  type(event.clipboardData ? event.clipboardData.getData("text/plain") : "");
}, true);

// Focus the native editor during the person's gesture; a delayed network callback cannot open an iOS keyboard.
function installKeyboard() {
  const screen = document.getElementById("noVNC_container");
  if (!screen || document.getElementById("signin_keyboard")) return;
  const panel = document.createElement("section");
  panel.id = "signin_keyboard";
  panel.setAttribute("aria-label", "Remote keyboard");
  panel.innerHTML = `
    <div class="actions"><button type="button" id="signin_show" aria-controls="signin_input" aria-pressed="false">Keyboard</button>
      <button type="button" id="signin_paste" hidden>Paste</button>
      <button type="button" id="signin_zoom" aria-pressed="false">Zoom</button></div>
    <input id="signin_input" type="password" inputmode="text" autocomplete="off" autocapitalize="off"
      autocorrect="off" spellcheck="false" enterkeyhint="done" aria-label="Type into the selected remote field"
      aria-describedby="signin_feedback">
    <p id="signin_feedback" role="status" aria-live="polite"></p>`;
  const style = document.createElement("style");
  style.textContent = `
    #signin_keyboard{position:fixed;inset:auto 0 0;z-index:11;box-sizing:border-box;padding:6px 10px;
      padding-bottom:max(6px,env(safe-area-inset-bottom));background:#fff;color:#161616;border-top:1px solid #ddd;
      font:14px/1.3 system-ui,sans-serif;touch-action:manipulation;user-select:text}
    #signin_keyboard .actions{display:flex;gap:6px}
    #signin_keyboard button{min-height:44px;padding:8px 12px;border:0;border-radius:8px;
      color:#161616;background:#eef2f3;font:14px system-ui;cursor:pointer;min-width:44px}
    #signin_zoom{margin-left:auto;background:transparent!important}
    #signin_keyboard button:disabled{opacity:.55;cursor:default}
    #signin_input{position:absolute;left:16px;top:16px;width:1px;height:1px;padding:0;border:0;
      opacity:.01;clip-path:inset(50%);font:16px system-ui;pointer-events:none}
    #signin_keyboard :focus-visible{outline:3px solid #075fba;outline-offset:2px}
    #signin_keyboard p{font-size:13px;margin:4px 0 0}
    #signin_feedback:empty{display:none}
    #signin_viewport{position:fixed;inset:0 0 var(--signin-keyboard-height,57px);overflow:auto;
      overscroll-behavior:contain;background:#fff}
    #noVNC_container{position:relative;border-radius:0;background:#fff}
    #noVNC_control_bar_anchor{display:none!important}
    #signin_keyboard [hidden]{display:none!important}
  `;
  document.head.appendChild(style);
  document.body.appendChild(panel);
  const viewport = document.createElement("div");
  viewport.id = "signin_viewport";
  screen.before(viewport);
  viewport.appendChild(screen);
  const input = panel.querySelector("input");
  const feedback = panel.querySelector("#signin_feedback");
  const show = panel.querySelector("#signin_show");
  const paste = panel.querySelector("#signin_paste");
  const zoom = panel.querySelector("#signin_zoom");
  let zoomed = false;
  function fitWidth() {
    const canvas = screen.querySelector("canvas");
    if (!canvas || !canvas.width || !canvas.height) return;
    const width = Math.floor(viewport.clientWidth * (zoomed ? 1.4 : 1));
    screen.style.width = `${width}px`;
    screen.style.height = `${Math.ceil(width * canvas.height / canvas.width)}px`;
  }
  zoom.addEventListener("pointerdown", event => event.preventDefault());
  zoom.addEventListener("click", () => {
    zoomed = !zoomed;
    zoom.textContent = zoomed ? "Reset zoom" : "Zoom";
    zoom.setAttribute("aria-pressed", String(zoomed));
    fitWidth();
  });
  // Let noVNC decode taps and two-finger remote scrolling; a one-finger drag pans this readable local view.
  let pan = null;
  for (const kind of ["gesturestart", "gesturemove", "gestureend"]) {
    screen.addEventListener(kind, event => {
      if (event.detail.type !== "drag") return;
      event.stopPropagation();
      const {clientX: x, clientY: y} = event.detail;
      if (kind === "gesturestart") pan = {x, y};
      if (pan && kind === "gesturemove") {
        viewport.scrollBy(pan.x - x, pan.y - y);
        pan = {x, y};
      }
      if (kind === "gestureend") pan = null;
    }, true);
  }
  // A non-secret sentinel gives mobile Backspace something to delete even after a previous edit was cleared.
  const sentinel = "_";
  let composing = false, rfb = null, previousFocusOnClick = true, ownsFocus = false, clipboardRequest = 0;
  let edit = {start: 1, end: 1, length: 1};
  function rememberEdit() {
    edit = {start: input.selectionStart, end: input.selectionEnd, length: input.value.length};
  }
  function reset() {
    input.value = sentinel;
    input.setSelectionRange(1, 1);
    rememberEdit();
  }
  function clear() {
    clipboardRequest++;
    composing = false;
    input.value = "";
    cancelTyping();
    if (rfb && ownsFocus) rfb.focusOnClick = previousFocusOnClick;
    ownsFocus = false;
    panel.classList.remove("signin_active");
    paste.hidden = true;
    show.textContent = "Keyboard";
    show.setAttribute("aria-pressed", "false");
  }
  function sync() {
    if (rfb !== UI.rfb) {
      clear();
      input.blur();
      rfb = UI.rfb;
      previousFocusOnClick = rfb ? rfb.focusOnClick : true;
      if (rfb && rfb.addEventListener) rfb.addEventListener("disconnect", sync);
      fitWidth();
    }
    const ready = connected();
    for (const control of panel.querySelectorAll("button,input")) control.disabled = !ready;
    if (!ready) {
      clear();
      input.blur();
      feedback.textContent = "Keyboard unavailable while disconnected.";
    } else if (feedback.textContent === "Keyboard unavailable while disconnected.") feedback.textContent = "";
    return ready;
  }
  function focus() {
    if (!sync()) return;
    reset();
    // focusOnClick=false prevents a subsequent canvas tap from stealing focus. It does not prevent VNC clicks.
    input.focus({preventScroll: true});
  }
  function editorReady() {
    // Synchronization clears ownership before a native event can reach a replacement viewer.
    return sync() && ownsFocus && document.activeElement === input;
  }
  function queue(keys) {
    if (!editorReady()) return;
    if (!enqueue(keys)) {
      feedback.textContent = "Input was not sent. Wait for pending typing; send at most 1000 characters at a time.";
    }
  }
  function send(text) {
    if (!editorReady() || !text) return;
    // Pasting a credential must never execute a newline/tab as a remote Submit or move to another field.
    // Reject the whole value rather than sending a silently changed or truncated password.
    if (/[\u0000-\u001f\u007f]/u.test(text)) {
      feedback.textContent = "Text containing line breaks, tabs or control characters was not sent.";
      return;
    }
    // A keysym lookup can succeed while x11vnc drops it on the virtual display. Do not send a partial credential.
    if (/[^\u0020-\u007e]/u.test(text)) {
      feedback.textContent = "Text was not sent. This remote keyboard supports English letters, numbers and symbols only.";
      return;
    }
    queue(Array.from(text).map(ch => keysyms.lookup(ch.codePointAt(0))));
  }
  function commit(inserted) {
    if (!editorReady()) { clear(); return; }
    let text = typeof inserted === "string" ? inserted : input.value;
    if (typeof inserted !== "string" && !(edit.start === 0 && edit.end > 0)) {
      // Track where the old sentinel survived the edit; a replacement's leading underscore is credential data.
      const index = edit.start === 0 ? text.length - (edit.length - (edit.end - edit.start)) : 0;
      if (text[index] === sentinel) text = text.slice(0, index) + text.slice(index + 1);
    }
    reset();
    send(text);
  }
  show.addEventListener("pointerdown", event => {
    if (document.activeElement === input) event.preventDefault();
  });
  show.addEventListener("click", () => {
    if (document.activeElement === input) { input.blur(); clear(); }
    else focus();
  });
  input.addEventListener("focus", () => {
    if (!sync()) return;
    feedback.textContent = "";
    // noVNC's delayed toolbar close focuses the canvas, dismissing a phone's keyboard mid-edit.
    UI.keepControlbar();
    previousFocusOnClick = rfb.focusOnClick;
    ownsFocus = true;
    rfb.focusOnClick = false;
    panel.classList.add("signin_active");
    paste.hidden = !navigator.clipboard?.readText;
    show.textContent = "Done";
    show.setAttribute("aria-pressed", "true");
    reset();
  });
  input.addEventListener("blur", clear);
  // noVNC's capture handlers must never interpret the native editor's keys as a second remote keystroke.
  for (const kind of ["keydown", "keyup"]) {
    document.addEventListener(kind, event => {
      if (event.target !== input) return;
      event.stopImmediatePropagation();
      if (!editorReady()) return;
      if (kind !== "keydown" || event.isComposing || composing) return;
      const keys = {Enter: "Return", Tab: "Tab", Backspace: "BackSpace", Delete: "Delete",
                    ArrowLeft: "Left", ArrowRight: "Right", ArrowUp: "Up", ArrowDown: "Down"};
      if (event.key === "Enter") {
        event.preventDefault(); input.blur(); clear(); return;
      }
      if (keys[event.key]) {
        event.preventDefault();
        if (event.key === "Tab") clipboardRequest++;
        queue([KeyTable[`XK_${keys[event.key]}`]]);
        reset();
      }
    }, true);
  }
  input.addEventListener("beforeinput", event => {
    if (!editorReady() || event.isComposing || composing) return;
    if (["insertLineBreak", "insertParagraph"].includes(event.inputType)) {
      event.preventDefault(); input.blur(); clear(); return;
    }
    rememberEdit();
    const keys = {deleteContentBackward: "BackSpace", deleteContentForward: "Delete"};
    if (keys[event.inputType] && event.cancelable) {
      event.preventDefault();
      queue([KeyTable[`XK_${keys[event.inputType]}`]]);
      reset();
    }
  });
  input.addEventListener("input", event => {
    if (!editorReady()) return;
    if (event.isComposing || composing) return;
    // compositionend has already committed; browsers may emit this final input afterward.
    if (event.inputType === "insertFromComposition") { reset(); return; }
    // Some mobile browsers emit a non-cancelable beforeinput for deletion.
    if (event.inputType === "deleteContentBackward" || event.inputType === "deleteContentForward") {
      queue([event.inputType === "deleteContentBackward" ? KeyTable.XK_BackSpace : KeyTable.XK_Delete]);
      reset();
    } else commit(event.data);
  });
  input.addEventListener("compositionstart", () => {
    if (!editorReady()) return;
    rememberEdit();
    composing = true;
  });
  input.addEventListener("compositionend", event => {
    if (!editorReady() || !composing) return;
    composing = false;
    // Commit before another native edit can begin; no shared timer may reset a newer composition.
    commit(event.data);
  });
  input.addEventListener("paste", event => {
    if (event.defaultPrevented) return;
    event.preventDefault();
    event.stopImmediatePropagation();
    if (!editorReady()) return;
    const text = event.clipboardData ? event.clipboardData.getData("text/plain") : "";
    // Replacing the editor can cancel the native IME without compositionend.
    composing = false;
    reset();
    send(text);
  });
  paste.addEventListener("pointerdown", event => event.preventDefault());
  paste.addEventListener("click", async () => {
    if (!editorReady() || !navigator.clipboard?.readText) return;
    const origin = UI.rfb, editGeneration = generation, request = ++clipboardRequest;
    try {
      const text = await navigator.clipboard.readText();
      if (request !== clipboardRequest || origin !== UI.rfb || editGeneration !== generation || !editorReady()) return;
      composing = false; reset(); send(text);
    } catch (_) {
      if (request === clipboardRequest && editorReady())
        feedback.textContent = "Paste was not allowed. Allow clipboard access and try Paste again.";
    }
  });
  screen.addEventListener("pointerdown", () => { cancelTyping(); if (ownsFocus) reset(); }, true);
  const stockButton = document.getElementById("noVNC_keyboard_button");
  if (stockButton) stockButton.addEventListener("click", event => {
    event.stopImmediatePropagation();
    show.click();
  }, true);
  const observer = new ResizeObserver(() => {
    document.documentElement.style.setProperty("--signin-keyboard-height", `${panel.offsetHeight}px`);
  });
  observer.observe(panel);
  const viewportObserver = new ResizeObserver(fitWidth);
  viewportObserver.observe(viewport);
  const canvasObserver = new MutationObserver(fitWidth);
  canvasObserver.observe(screen, {subtree:true, childList:true, attributes:true, attributeFilter:["width", "height"]});
  fitWidth();
  const timer = setInterval(sync, 250);
  document.addEventListener("visibilitychange", () => { if (document.hidden) { clear(); input.blur(); } });
  window.addEventListener("pagehide", () => {
    clear(); input.blur(); clearInterval(timer); observer.disconnect();
    viewportObserver.disconnect(); canvasObserver.disconnect();
  });
  sync();
}
if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", installKeyboard, {once: true});
else installKeyboard();
