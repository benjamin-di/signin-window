# Working on signin-window

Instructions for contributors and coding agents. `AGENTS.md` is the only agent instruction file.

**This repository is public.** Never commit personal data or anything about a particular deployment: no names,
email addresses, accounts, host names, networks or infrastructure of where it runs, and no anecdotes about who used
it when. Tests and examples use `example.com` and invented values. This applies to code comments, docs, tests and
commit messages alike.

## Verify

`make bootstrap`, then `make check`: ruff, the format check and pytest. The paste add-on's browser test runs with
`uv sync --group browser`, `uv run playwright install chromium` and `uv run pytest tests/test_paste_dom.py` (CI runs
it in the `test` job after `make check`; the `e2e` job runs in the prebuilt `signin-window-e2e` image).
Documentation-only changes need `git diff --check` and link checks.

## Boundaries

- `tests/test_safety.py` is the boundary: human window/relay modules never import optional `automation`, and never
  click, type or fill a page. Optional automation has separate contracts and must receive its planner explicitly.
  Only `client.py` opens
  connections to the login service. Optional `oidc.py` uses Authlib for the configured
  identity provider only; applications own identity-to-account mapping and all account
  controls. Human window/relay imports never require the OIDC extra. The VNC server
  listens on loopback; `static/paste.js` logs and keeps nothing.
  Changing any of these is a design change: argue it in the pull request.
- Session helpers share durable accounting and warm-first mechanics. Applications
  own site identity, entitlement, publication formats and maintenance policy.
  Automation changes require synthetic browser evidence for acceptance, stale
  task rejection and bounded failure; human APIs remain independent of them.
- The login service's live view is open only while a window is `waiting` and only with its view token; a link's
  live view only while its window is `waiting`. A session crosses from the service to the server once
  (`POST /logins/{id}/result`) and is never part of a state, a page or a log line.
- `static/paste.js` is noVNC-version-sensitive (it imports `app/ui.js` and the keysym tables): test it against the
  noVNC release the README names.
- The public API is what `README.md` documents. Within 0.x, a minor version may change it; say how in the release
  notes.
