# signin-window roadmap

Prioritize fewer repeated sign-ins, predictable recovery and less duplicated
maintenance code in adopting applications. Keep the existing browser stack and
the separation between human sign-in and explicitly authorized automation.

Work proceeds in the order below. Each phase needs acceptance evidence before
consumer upgrades; no phase requires a new browser service or workflow engine.

## Available foundation

The 0.4.4 release already provides durable attempt budgets, warm-first reuse,
refresh scheduling, ordered leases and private-state helpers. Optional APIs
include `MaintenanceStateStore`, `CredentialReader`, `CredentialFiller` and the
1Password adapters `OpCredentialReader` and `OpSecretFiller`. Prefer adopting
these APIs to creating another implementation.

Applications continue to own account identity, entitlement checks, session
formats, maintenance policy and publication. A successful sign-in or cleared
challenge does not establish usable application access.

## Phase 1 Reliable completion and expiry

Define the lifecycle from sign-in through verification, saving and
acknowledgement. Design a bounded, acknowledged handover so temporary transport
or saving failures can be reconciled without unnecessarily repeating sign-in.
Keep session transfer private and bound to the original authenticated consumer.
Any result-protocol change must document the one-time ownership-transfer
contract and the migration path for existing clients.

Complete saving independently of page polling. Enforce deadlines and cleanup
without requiring another API request. Let an accepted save finish within a
bounded period; serialize replacement so an older attempt cannot overwrite a
newer accepted publication. Preserve the previous verified artifact until its
replacement is accepted by the application.

Distinguish verification failure, saving failure and uncertain completion in
the page and API. Persisted attempt metadata alone does not preserve a browser
process: report interruption accurately when reattachment is unavailable.

**Complete when:** synthetic tests cover saving failure, lost acknowledgement,
concurrent completion, replacement during saving and expiry without polling.
Recovery does not duplicate publication, expose a session or replay credentials.

## Phase 2 Reload recovery and password manager usability

Reattach a reloaded page to its current active attempt. Provide an explicit
Cancel action and a short disconnect grace period bounded by the attempt's
deadline. Show reconnecting, waiting, verifying and saving states. An accepted
save continues after the viewer closes.

Document using a password manager such as 1Password on the person's own device
to copy and paste a password or code into the remote window. Improve mobile
paste controls and keyboard guidance without collecting credentials in a chat
or model context. Keep clipboard contents out of logs and persistent storage.

Explain authentication capabilities before opening a window:

- A provider's native OAuth flow in the person's own browser can use that
  browser's normal password manager and supported passkeys.
- The remote viewer does not give the server's browser access to the person's
  local 1Password extension or authenticator. Standard cross-device passkey
  authentication uses proximity checks; displaying a QR code is not a general
  solution for a distant server.
- A remote window offers the site's other supported sign-in methods. Do not
  describe choosing an alternative method as passkey support.

**Complete when:** browser acceptance covers reload without a second window,
brief disconnect and reconnect, explicit cancellation, grace-period expiry,
completion after viewer closure, and password/code paste on supported desktop
and phone browsers. Include Unicode and keyboard regression cases.

## Phase 3 Shared maintenance and existing 1Password support

Adopt `MaintenanceStateStore` where applications duplicate hold, cooldown and
publication-watermark persistence. Preserve existing schemas, compare-and-clear
acknowledgement, consumed attempts and generation ordering. Keep account checks,
limits, schedules and snapshot contents in the applications.

Move browser ownership and shutdown helpers needed by human runners into a
neutral module, with compatibility imports during migration. Human APIs must
remain independent of credential automation.

Document and qualify the existing optional 1Password adapter for authorized
maintenance. Resolve only configured username, password and generated TOTP
fields, just in time, with read-only access scoped to the required vaults.
Preserve origin/document checks and redacted errors. A failed lookup never
falls back to another identity or backend. Password/TOTP resolution does not
constitute passkey authentication.

**Complete when:** adopting applications use the shared APIs with unchanged
state formats and policy. Regression tests cover origin changes, unavailable
credentials, invalid TOTP, error redaction and preserved holds/budgets. Imports
and availability checks do not read credentials; human-only use gains no vault
access.

## Phase 4 Supported consumer upgrades

Bring existing consumers onto a supported release line through their own gates
and synthetic browser acceptance. Preserve upstream behavior and public routes.
Document coordinated client/server upgrades where a protocol change requires
them, including compatibility and rollback behavior.

Preserve runtime state through upgrades and rollback. Do not reset attempts,
clear holds or acknowledge an uncertain publication as part of installation.
Keep deployment inventories and account-specific configuration with the
adopting application or deployment.

**Complete when:** existing consumers use supported releases, their relevant
checks pass, and each has a documented upgrade path. Current library fixes must
reach consumers before expanding the library's scope.

## Later evaluation of user approved 1Password autofill

After the core phases, evaluate the official 1Password Agentic Autofill
integration in an application that already uses a supported browser service.
The intended flow is a request for one login, approval on the person's device,
provider-managed filling, then independent application verification.

First verify current account, region, plan and integration-registration
requirements. Use a synthetic login to demonstrate approval, denial, timeout
and successful verification, with credentials excluded from model context,
application logs and recordings. Confirm passkey capabilities separately;
password autofill is not evidence of passkey support.

Only extract library support after the application proves a direct benefit and
a small reusable interface. This evaluation does not justify changing the
default browser backend or installing an unlocked personal-vault extension in
a shared remote browser.

## Deferred scope

General remote passkey support needs a supported authenticator or credential
broker available to the browser performing authentication. Reconsider it when
an adopting application has a concrete need and a supported mechanism is
demonstrated. Custom WebAuthn bridges, passkey export and production virtual
authenticators are outside this roadmap.

Also defer new browser backends, local-browser extensions, a universal
authentication/status framework, mandatory databases or workflow engines, and
additional login-provider or CAPTCHA automation. Revisit them only against a
measurable problem in an existing application.

## Evidence and completion

Use existing test harnesses, logs and release tooling. Establish a baseline for
repeat sign-ins caused by infrastructure failures, successful reconnects and
abandoned-window cleanup. Record duplicated maintenance code removed during
adoption; do not add an observability service for this roadmap.

The roadmap is complete when the core improvements are adopted by existing
consumers. Further expansion needs a demonstrated user or maintenance benefit.
