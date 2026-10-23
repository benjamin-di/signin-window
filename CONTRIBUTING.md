# Contributing

Thanks for helping. Issues and pull requests are welcome.

## Setup

```sh
git clone https://github.com/benjamin-di/signin-window
cd signin-window
make bootstrap   # uv sync --locked
make check       # lint, format, tests
```

The paste add-on's browser test needs Playwright's Chromium:
`uv sync --group browser && uv run playwright install chromium && uv run pytest tests/test_paste_dom.py`.

## Rules

- **The person does every step of a sign-in.** Nothing in this package may click, type or fill a page
  (`tests/test_safety.py`). A change that automates a sign-in will not be taken.
- **Only `client.py` talks to the network**, and only to the login service.
- **No personal data** in code, tests, fixtures, docs or commit messages: use `example.com` and invented values.
- Keep the API stable within a minor version; say in the pull request what a change does to existing users.

AGENTS.md has the same rules for coding agents.

## How changes land

Each release of this repository is exported from a private working repository as one
`Release X.Y.Z` commit, so pull requests are not merged here: the next release would replace
them. When a change fits, the maintainer applies it there, credits you in the release notes
and closes the pull request with a link to the release that contains it. Issues are welcome;
answers are best effort.
