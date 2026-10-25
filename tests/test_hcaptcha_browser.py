"""Inert browser regressions for task identity during slow planning."""

import time
from types import SimpleNamespace

import pytest

from signin_window.automation.challenges import ChallengeAcceptance, ChallengeAcceptanceSource
from signin_window.automation.hcaptcha import HCaptchaVisualMechanic, _ActionBoundary
from signin_window.automation.plans import VisualPlan

try:
    from playwright.sync_api import sync_playwright
except ImportError:
    sync_playwright = pytest.importorskip("patchright.sync_api").sync_playwright


@pytest.fixture(scope="module")
def chromium():
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        try:
            yield browser
        finally:
            browser.close()


def test_next_advances_the_task_without_claiming_acceptance(chromium):
    context = chromium.new_context()
    context.route(
        "**/*",
        lambda route: route.fulfill(
            content_type="text/html",
            body="<button>Skip</button><button id='submit'>Next</button>",
        ),
    )
    try:
        page = context.new_page()
        page.set_content("<iframe src='https://fixture.hcaptcha.invalid/?frame=challenge'></iframe>")
        frame = page.frames[-1]
        frame.wait_for_selector("#submit")
        frame.evaluate("""() => {
          window.clicks = [];
          window.accepted = false;
          document.addEventListener('click', event => {
            if (event.target.tagName !== 'BUTTON') return;
            window.clicks.push(event.target.textContent);
            if (event.target.textContent === 'Next') {
              event.target.textContent = 'Verify';
            } else if (event.target.textContent === 'Verify') {
              window.accepted = true;
            }
          });
        }""")

        class Probe:
            def observe(self):
                accepted = frame.evaluate("() => window.accepted")
                return ChallengeAcceptance(
                    accepted=accepted,
                    source=ChallengeAcceptanceSource.EXISTING_FORM_FIELD
                    if accepted
                    else ChallengeAcceptanceSource.NONE,
                )

        mechanic = HCaptchaVisualMechanic(planner=SimpleNamespace())
        probe = Probe()

        def advance(*, expired=False):
            deadline = time.monotonic() + (-1 if expired else 5)
            return mechanic._wait_and_click_submit(
                page,
                frame,
                deadline=deadline,
                acceptance=probe,
                boundary=_ActionBoundary(lambda: None, lambda: deadline - time.monotonic()),
            )

        assert not advance(expired=True)
        assert frame.evaluate("() => window.clicks") == []
        assert advance()
        assert not probe.observe().accepted
        assert frame.evaluate("() => window.clicks") == ["Next"]
        assert advance()
        assert probe.observe().accepted
        assert not advance()
        assert frame.evaluate("() => window.clicks") == ["Next", "Verify"]
    finally:
        context.close()


@pytest.mark.parametrize("change", ["animation", "task_node", "asset", "frame"])
def test_planner_can_only_act_on_its_original_task(chromium, change, monkeypatch, tmp_path):
    page = chromium.new_page()
    clicks = []
    click = page.mouse.click

    def observed_click(*args, **kwargs):
        clicks.append("fixture-click")
        return click(*args, **kwargs)

    monkeypatch.setattr(page.mouse, "click", observed_click)
    fixture = """
      <div class='challenge-view' style='width:200px;height:200px;background:white'>
        <h2 class='prompt-text'>Click the moving object</h2>
        <div class='task-image'>
          <img width='60' height='60'
            src='data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7'>
        </div>
        <button>Verify</button>
      </div>
    """
    page.route("**/*", lambda route: route.fulfill(content_type="text/html", body=fixture))
    try:
        page.set_content(
            "<iframe width='300' height='300' src='https://fixture.hcaptcha.invalid/?frame=challenge'></iframe>"
        )
        frame = page.frames[-1]
        frame.wait_for_selector(".task-image img")
        frame.evaluate("""() => {
          window.accepted = false;
          document.addEventListener('click', () => {
            window.accepted = true;
          });
        }""")

        class Probe:
            def observe(self):
                accepted = not frame.is_detached() and frame.evaluate("() => window.accepted") is True
                return ChallengeAcceptance(
                    accepted=accepted,
                    source=ChallengeAcceptanceSource.EXISTING_FORM_FIELD
                    if accepted
                    else ChallengeAcceptanceSource.NONE,
                )

        class Planner:
            def plan(self, image, **kwargs):
                if change == "animation":
                    frame.evaluate("() => document.querySelector('img').style.transform = 'translateX(20px)'")
                elif change == "task_node":
                    frame.evaluate("""() => {
                      const node = document.querySelector('.task-image');
                      node.replaceWith(node.cloneNode(true));
                    }""")
                elif change == "asset":
                    frame.evaluate("() => document.querySelector('img').src += '#replacement'")
                else:
                    page.evaluate("""() => {
                      const node = document.querySelector('iframe');
                      node.replaceWith(node.cloneNode(true));
                    }""")
                return VisualPlan(kind="point", points=({"x": 0.5, "y": 0.5},))

        browser = SimpleNamespace(page=page)
        result = HCaptchaVisualMechanic(planner=Planner(), max_rounds=1).solve(browser, Probe())
        assert result.accepted is (change == "animation")
        assert clicks == (["fixture-click"] if change == "animation" else [])
    finally:
        page.close()
