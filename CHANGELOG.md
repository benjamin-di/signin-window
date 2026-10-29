# Changelog

## Unreleased

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
