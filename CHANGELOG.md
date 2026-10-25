# Changelog

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
