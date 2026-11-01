# Changelog

## [0.5.1] - 2026-11-01

### Fixed

- Sign private-key client assertions for the configured issuer with a fresh assertion identifier for every exchange, refresh and revocation.
- Keep the unsafe-activity-link fixture aligned with the reviewed synthetic credential fixture so the public export can publish the optional delegation and connection controls (#2).

### Upgrade

- Action required: none.
- Rollback: compatible with 0.5.0; use 0.5.1 for public package installation.

## [0.5.0] - 2026-11-01

_Yanked: public package publication was blocked by a synthetic test fixture; use 0.5.1._

_Releases 0.4.3–0.4.17 were not recorded by version here; see their tags._

### Added

- Add the optional `delegation` extra with `OAuthConfig` and `OAuthManager` for encrypted per-owner grants, PKCE connection tickets, serialized refresh, durable disconnect and private-key client authentication (8fe8348).
- Add `DirectOAuthManager` for single-consent entry before the owner is known, with signed identity validation, resource owner proof and durable reconnection barriers (214039f).
- Add optional `ConnectionControls` and `controls_panel` for pause, granted scopes and recent activity on hosted Connections pages (1ff25e5).
- Add explicit `callback_path`, `owner_header` and `cookie_name` configuration while preserving existing OAuth defaults (fdf0f41).

### Upgrade

- Action required: none for existing consumers; install `signin-window[delegation]` and configure provider, resource, private storage and application identity to adopt the new APIs.
- Rollback: compatible with 0.4.17 for existing APIs; consumers adopting delegation or controls must retain 0.5.0 until their integration is removed.

[0.5.0]: https://github.com/benjamin-di/signin-window/releases/tag/v0.5.0

## Prior unversioned release notes (through 0.4.17)

- The 1Password reader accepts a 1Password Connect server from the
  environment (`OP_CONNECT_HOST` and `OP_CONNECT_TOKEN`), which takes
  precedence over `OP_SERVICE_ACCOUNT_TOKEN` as in `op` and is passed to `op`
  alone. An explicit `service_account_token` remains the only identity.
- The 1Password reader now passes `OP_CONFIG_DIR` to `op`. Without it, `op`
  failed to create its configuration directory in read-only containers, so
  every credential read failed.
- A sign-in the provider authenticated within the last five minutes now counts
  as a fresh confirmation (`reauthenticated_at` is its verified `auth_time`), so
  a sensitive action straight after sign-in needs no second authentication.
- Sign-out answers with a signed-out page instead of redirecting home.
- Add `PageText(auto_start=True)` for owner-bound links: the window opens on load.

- Add optional, provider-neutral OIDC browser sessions through Authlib, with
  code/PKCE/nonce validation, one-use callbacks, secure opaque cookies, and
  explicit fresh-authentication support. Applications retain account ownership,
  permission checks, credential publication and durable disconnect controls.

- Add provider-neutral authenticated attempts with private owner, requester and
  target context, route authorization, same-origin mutations and continuously
  authorized viewer streams. Existing capability links remain supported.
- Reap viewer pipes on cancellation, remove control while saving, improve status
  accessibility and provide safe local return navigation. Uncertain completion
  no longer claims that nothing was saved.

- Add retained-profile child completion, acknowledged control revocation before
  publication, and configurable cancellation cleanup grace.
- Add a synthetic LinkedIn adapter that preserves upstream browser launch,
  profile leasing, rotation, cookie export and session restoration.

- Add `LocalBackend` for embedded human viewers, and borrow an existing display
  without taking ownership of it.
- Add host lifespans for autonomous window expiry, bounded accepted saves and
  completion reconciliation without page polls.
- Add opt-in page reload recovery and explicit cancellation; retain legacy page
  behavior by default. The remote result-transfer protocol remains unchanged.
- Add an Amazon prototype using application-owned verification and publication,
  with synthetic real-browser acceptance and prepared upstream hooks.

## 0.4.2

- Add passive challenge detection and bounded resolver orchestration. Callers
  still select permitted mechanics and verify application access themselves.
- Expose a filtered Chromium environment for human and maintenance runners,
  and reusable shutdown for explicitly owned browser processes.
- Reject nonregular and oversized private state without blocking; importing
  pure scheduling helpers no longer requires POSIX locks.

## 0.4.1

- Add optional Google sign-in mechanics with configured controls, observations,
  callback checks and injected credential delivery. Application access remains
  the caller's responsibility.
- Add an origin-bound 1Password adapter using only the supplied service identity.
- Add a maintenance browser facade, isolated virtual display and owned Chromium
  lifetime. Browser children receive runtime settings without operator or planner
  credentials; persistent profiles survive clean shutdown and reopening.
- Add the `chromium` extra. Human window, relay and paste APIs keep their existing
  behavior and never import or start optional automation.

## 0.4.0

- Share durable private state, ordered file leases, rolling attempt accounting,
  warm-first maintenance and refresh scheduling.
- Add optional bounded hCaptcha and reCAPTCHA mechanics, typed visual plans,
  native X11 pointer input and safe Chromium profile ownership.
- Require explicit planners in shared challenge mechanics. Applications retain
  identity verification, entitlement checks, state formats and maintenance policy.

[0.5.1]: https://github.com/benjamin-di/signin-window/releases/tag/v0.5.1
