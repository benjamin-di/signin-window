"""Synthetic native-editor checks. These cannot establish physical iOS keyboard opening."""

import json
from urllib.parse import urlsplit

import pytest
from test_paste_dom import ADD_ON, MODULES, VIEWER

sync_api = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def mobile_browser():
    with sync_api.sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        yield browser
        browser.close()


@pytest.fixture(params=[320, 390, 1280])
def mobile(request, mobile_browser):
    modules = dict(MODULES)
    modules["/core/input/keysym.js"] = """export default {
      XK_Return: 0xff0d, XK_Tab: 0xff09, XK_BackSpace: 0xff08, XK_Delete: 0xffff,
      XK_Left: 0xff51, XK_Right: 0xff53, XK_Up: 0xff52, XK_Down: 0xff54,
      XK_Shift_L: 0xffe1, XK_Control_L: 0xffe3, XK_Control_R: 0xffe4,
      XK_Alt_L: 0xffe9, XK_Super_L: 0xffeb, XK_Super_R: 0xffec,
    };"""
    html = VIEWER.replace("<body></body>", "<body><div id=noVNC_container><canvas tabindex=0></canvas></div></body>")
    html = html.replace("viewOnly: false,", "viewOnly: false, focusOnClick: true,")
    html = html.replace(
        "if (down === undefined) state.typed += String.fromCodePoint(keysym);",
        """
      if (down === undefined) {
        state.keys = JSON.stringify([...(JSON.parse(state.keys || '[]')), keysym]);
        if (keysym === 0xff08) state.typed = Array.from(state.typed).slice(0, -1).join('');
        else if (keysym < 0xff00 || keysym > 0xffff) state.typed += String.fromCodePoint(keysym);
      }
    """,
    )
    html = html.replace("  UI.rfb = {", "  window.testUI = UI; UI.rfb = {")
    files = {"/vnc.html": ("text/html", html), "/paste.js": ("text/javascript", ADD_ON.read_text())}
    files.update({path: ("text/javascript", body) for path, body in modules.items()})

    def serve(route):
        url = urlsplit(route.request.url)
        found = files.get(url.path) if url.netloc == "viewer.example" else None
        if found:
            route.fulfill(content_type=found[0], body=found[1])
        else:
            route.abort()

    context = mobile_browser.new_context(viewport={"width": request.param, "height": 844}, has_touch=True)
    page = context.new_page()
    page.add_init_script("""document.addEventListener('paste', event => {
      if (window.pasteEvents) window.pasteEvents.push(event.isTrusted);
    }, true);""")
    page.route("**/*", serve)
    page.goto("https://viewer.example/vnc.html")
    page.get_by_role("button", name="Show keyboard", exact=True).click()
    yield page
    context.close()


def typed(page, expected):
    page.wait_for_function("v => document.documentElement.dataset.typed === v", arg=expected)


def paste(page, value):
    page.evaluate(
        """text => {
      const clipboardData = new DataTransfer(); clipboardData.setData('text/plain', text);
      document.getElementById('signin_input').dispatchEvent(new ClipboardEvent('paste', {
        clipboardData, bubbles: true, cancelable: true,
      }));
    }""",
        value,
    )


def test_focus_typing_and_privacy(mobile):
    editor = mobile.locator("#signin_input")
    assert editor.evaluate("e => e === document.activeElement")
    assert editor.get_attribute("type") == "password"
    assert editor.get_attribute("autocomplete") == "off"
    mobile.keyboard.insert_text("user@example.com")
    typed(mobile, "user@example.com")
    assert editor.input_value() == "_"
    assert mobile.evaluate("testUI.rfb.focusOnClick") is False
    mobile.get_by_role("button", name="Hide keyboard", exact=True).click()
    assert editor.input_value() == ""
    assert mobile.evaluate("testUI.rfb.focusOnClick") is True


def test_paste_password_then_code_and_repeated_backspace(mobile):
    paste(mobile, "sYnth3tic! ")
    # New native input during a paced paste must be queued, never silently dropped.
    mobile.keyboard.insert_text("123456")
    typed(mobile, "sYnth3tic! 123456")
    for _ in range(3):
        mobile.keyboard.press("Backspace")
    typed(mobile, "sYnth3tic! 123")
    mobile.get_by_role("button", name="Backspace", exact=True).click()
    typed(mobile, "sYnth3tic! 12")
    assert mobile.locator("#signin_input").evaluate("e => e === document.activeElement")
    assert mobile.locator("#signin_input").input_value() == "_"
    assert mobile.locator("html").get_attribute("data-reads") == "0"


@pytest.mark.parametrize("transition", ["blur", "replacement", "disconnect"])
@pytest.mark.parametrize("destination", ["canvas", "native"])
def test_desktop_paste_cannot_outlive_its_original_viewer(mobile, transition, destination):
    mobile.locator("#signin_input").evaluate("e => e.blur()")
    mobile.context.grant_permissions(["clipboard-read", "clipboard-write"])
    mobile.evaluate("delete navigator.clipboard")
    mobile.evaluate("navigator.clipboard.writeText('7890')")
    mobile.locator("canvas").focus()
    mobile.evaluate(
        """({transition, destination}) => {
      window.pasteEvents = [];
      document.addEventListener('keydown', function changeViewer(event) {
        if (event.code !== 'KeyV') return;
        document.removeEventListener('keydown', changeViewer, true);
        if (transition === 'replacement') testUI.rfb = {...testUI.rfb};
        if (transition === 'disconnect') testUI.rfb._rfbConnectionState = 'disconnected';
        const show = document.getElementById('signin_show');
        show.focus();
        show.click();
        if (destination === 'native' && transition === 'blur') {
          document.getElementById('signin_input').blur();
          show.focus();
          show.click();
        }
        if (destination === 'canvas') document.getElementById('signin_input').blur();
        testUI.rfb._rfbConnectionState = 'connected';
        if (destination === 'canvas') document.querySelector('canvas').focus();
      }, true);
    }""",
        {"transition": transition, "destination": destination},
    )
    # Chromium's default trusted paste runs after keydown listeners, just as
    # a viewer can be replaced between the paste gesture and its native event.
    mobile.keyboard.press("Control+V")
    mobile.wait_for_timeout(400)
    assert mobile.evaluate("pasteEvents") == [True]
    assert mobile.locator("html").get_attribute("data-typed") == ""
    assert mobile.locator("#signin_feedback").inner_text()
    # A new paste gesture belongs to the current viewer and remains usable.
    mobile.keyboard.press("Control+V")
    typed(mobile, "7890")


@pytest.mark.parametrize("value", ["a\nb", "a\tb", "a\rb", "a\x01b", "_päss文9😀", "ä", "文", "😀", "x" * 1001])
def test_unsupported_or_oversized_mobile_paste_is_rejected_as_a_whole(mobile, value):
    paste(mobile, value)
    assert mobile.locator("html").get_attribute("data-typed") == ""
    assert mobile.locator("#signin_feedback").inner_text()
    assert mobile.locator("#signin_input").input_value() == "_"


def test_composition_commits_once(mobile):
    editor = mobile.locator("#signin_input")
    editor.dispatch_event("compositionstart")
    editor.evaluate("e => {e.value = '_Pass9!'; e.dispatchEvent(new InputEvent('input', {isComposing:true}));}")
    assert mobile.locator("html").get_attribute("data-typed") == ""
    editor.evaluate("""e => {
      e.dispatchEvent(new CompositionEvent('compositionend', {data:'Pass9!'}));
      e.dispatchEvent(new InputEvent('input', {inputType:'insertFromComposition'}));
    }""")
    typed(mobile, "Pass9!")
    mobile.wait_for_timeout(100)
    assert mobile.locator("html").get_attribute("data-typed") == "Pass9!"
    assert editor.input_value() == "_"


def test_refusal_feedback_survives_following_keystrokes(mobile):
    mobile.keyboard.insert_text("p")
    typed(mobile, "p")
    mobile.keyboard.insert_text("ä")
    warning = mobile.locator("#signin_feedback").inner_text()
    assert warning
    mobile.keyboard.insert_text("ss9")
    typed(mobile, "pss9")
    assert mobile.locator("#signin_feedback").inner_text() == warning
    mobile.get_by_role("button", name="Hide keyboard", exact=True).click()
    mobile.get_by_role("button", name="Show keyboard", exact=True).click()
    assert mobile.locator("#signin_feedback").inner_text() == ""


def test_mobile_beforeinput_and_editing_keys(mobile):
    mobile.keyboard.insert_text("ab")
    typed(mobile, "ab")
    editor = mobile.locator("#signin_input")
    editor.evaluate("""e => e.dispatchEvent(new InputEvent('beforeinput', {
      inputType:'deleteContentBackward', cancelable:true,
    }))""")
    typed(mobile, "a")
    editor.evaluate("""e => {
      e.value = ''; e.dispatchEvent(new InputEvent('input', {inputType:'deleteContentBackward'}));
    }""")
    typed(mobile, "")
    mobile.get_by_role("button", name="Tab", exact=True).click()
    mobile.get_by_role("button", name="Enter", exact=True).click()
    mobile.wait_for_function("JSON.parse(document.documentElement.dataset.keys).slice(-2).join(',') === '65289,65293'")


def test_replacement_connection_cannot_receive_pending_input(mobile):
    paste(mobile, "x" * 100)
    mobile.evaluate("""() => {
      const old = testUI.rfb;
      testUI.rfb = {...old, sendKey(k, c, down) {
        if (down === undefined) document.documentElement.dataset.newKeys = 'unexpected';
      }};
    }""")
    mobile.wait_for_timeout(400)
    assert mobile.locator("html").get_attribute("data-new-keys") is None
    assert mobile.locator("#signin_input").input_value() == ""


def test_native_deletion_cannot_cross_viewer_replacement(mobile):
    result = mobile.evaluate("""() => {
      const editor = document.getElementById('signin_input');
      editor.value = '_';
      editor.select();
      const old = testUI.rfb;
      const keys = [];
      testUI.rfb = {...old, sendKey(k, c, down) { if (down === undefined) keys.push(k); }};
      const deleted = document.execCommand('delete');
      return {deleted, keys, focused: document.activeElement === editor, value: editor.value};
    }""")
    assert result == {"deleted": True, "keys": [], "focused": False, "value": ""}
    mobile.get_by_role("button", name="Show keyboard", exact=True).click()
    assert mobile.locator("#signin_input").evaluate("e => e === document.activeElement")


def test_disconnect_clears_composition_and_queue(mobile):
    paste(mobile, "x" * 100)
    mobile.evaluate("testUI.rfb._rfbConnectionState = 'disconnected'")
    mobile.wait_for_timeout(400)
    assert mobile.locator("#signin_input").is_disabled()
    assert mobile.locator("#signin_input").input_value() == ""
    assert len(mobile.locator("html").get_attribute("data-typed")) < 100


def test_native_editor_does_not_forward_keys_twice(mobile):
    # Model noVNC's canvas listener at an ancestor: editor events must never reach it.
    mobile.evaluate("""() => document.addEventListener('keydown', () => {
      document.documentElement.dataset.leaked = 'yes';
    }, true)""")
    mobile.keyboard.insert_text("a")
    mobile.keyboard.press("Backspace")
    mobile.keyboard.press("Enter")
    mobile.wait_for_timeout(100)
    assert mobile.locator("html").get_attribute("data-leaked") is None
    assert json.loads(mobile.locator("html").get_attribute("data-keys")) == [97, 65288, 65293]


def test_controls_fit_the_viewport(mobile):
    for element in mobile.locator("#signin_keyboard button, #signin_input").all():
        box = element.bounding_box()
        assert box and box["height"] >= 44
        assert box["x"] >= 0 and box["x"] + box["width"] <= mobile.viewport_size["width"]


@pytest.mark.parametrize("selection,text", [((0, 1), "_Ab9!"), ((0, 0), "Ab9!"), ((1, 1), "_Ab9!")])
def test_native_selection_or_caret_never_changes_credential_data(mobile, selection, text):
    mobile.locator("#signin_input").evaluate("(e, s) => e.setSelectionRange(...s)", selection)
    mobile.keyboard.insert_text(text)
    typed(mobile, text)
    assert mobile.locator("#signin_input").input_value() == "_"


def test_composition_replacing_selected_sentinel_preserves_leading_underscore(mobile):
    editor = mobile.locator("#signin_input")
    editor.evaluate("e => e.select()")
    editor.dispatch_event("compositionstart")
    editor.evaluate("""e => {
      e.value = '_Ab9!';
      e.dispatchEvent(new InputEvent('input', {isComposing:true}));
      e.dispatchEvent(new CompositionEvent('compositionend', {data:'_Ab9!'}));
      e.dispatchEvent(new InputEvent('input', {inputType:'insertFromComposition'}));
    }""")
    typed(mobile, "_Ab9!")
    mobile.wait_for_timeout(100)
    assert mobile.locator("html").get_attribute("data-typed") == "_Ab9!"


def test_rapid_native_compositions_preserve_every_completed_edit(mobile):
    cdp = mobile.context.new_cdp_session(mobile)
    sequence = [("Control+A", "_Ab9!"), ("Home", "Ab9!"), ("End", "_XYZ")] * 4
    for key, value in sequence:
        mobile.keyboard.press(key)
        cdp.send("Input.imeSetComposition", {"text": value, "selectionStart": len(value), "selectionEnd": len(value)})
        cdp.send("Input.insertText", {"text": value})
    typed(mobile, "".join(value for _, value in sequence))
    assert mobile.locator("#signin_feedback").inner_text() == ""
    assert mobile.locator("#signin_input").input_value() == "_"


def test_native_composition_followed_immediately_by_plain_text(mobile):
    cdp = mobile.context.new_cdp_session(mobile)
    for _ in range(12):
        cdp.send("Input.imeSetComposition", {"text": "A9", "selectionStart": 2, "selectionEnd": 2})
        cdp.send("Input.insertText", {"text": "A9"})
        mobile.keyboard.insert_text("Z")
    typed(mobile, "A9Z" * 12)


def test_native_paste_during_composition_keeps_following_typing(mobile):
    mobile.context.grant_permissions(["clipboard-read", "clipboard-write"])
    # The desktop-paste fixture removes the Clipboard prototype to test its fallback.
    mobile.evaluate("delete navigator.clipboard")
    mobile.evaluate("navigator.clipboard.writeText('_Paste9!')")
    cdp = mobile.context.new_cdp_session(mobile)
    cdp.send("Input.imeSetComposition", {"text": "UNCOMMITTED9", "selectionStart": 12, "selectionEnd": 12})
    mobile.keyboard.press("Control+V")
    mobile.keyboard.insert_text("NEXT9!")
    typed(mobile, "_Paste9!NEXT9!")
    assert mobile.locator("#signin_input").input_value() == "_"
    assert mobile.locator("#signin_feedback").inner_text() == ""


@pytest.mark.parametrize("action", ["keyboard", "beforeinput", "input", "button"])
def test_full_queue_refusal_is_visible_for_every_editing_entrypoint(mobile, action):
    # All actions occur in one browser task so the paced queue cannot drain first.
    mobile.evaluate(
        """action => {
      const input = document.getElementById('signin_input');
      const clipboardData = new DataTransfer(); clipboardData.setData('text/plain', 'A'.repeat(1000));
      input.dispatchEvent(new ClipboardEvent('paste', {clipboardData, cancelable:true, bubbles:true}));
      for (let i = 0; i < 8; i++) {
        if (action === 'keyboard') input.dispatchEvent(new KeyboardEvent('keydown', {
          key:'Backspace', bubbles:true, cancelable:true,
        }));
        else if (action === 'button') document.querySelector('[data-key="BackSpace"]').click();
        else input.dispatchEvent(new InputEvent(action, {
          inputType:'deleteContentBackward', cancelable:action === 'beforeinput', bubbles:true,
        }));
      }
    }""",
        action,
    )
    assert "Input was not sent" in mobile.locator("#signin_feedback").inner_text()
